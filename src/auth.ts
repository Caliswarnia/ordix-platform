// Sign-in for agency staff and client teams: email + password, then a 6-digit authenticator
// code (TOTP, RFC 6238). First sign-in sets up the authenticator and replaces the temporary
// password. A person in several agencies picks a workspace; every request then runs inside it.
//
//   POST /auth/sign-in    { email, password }       -> { next: 'code' | 'enroll', challenge, [secret, otpauth] }
//   POST /auth/verify     { challenge, code }       -> session cookie; the signed-in person
//   POST /auth/workspace  { membershipId }          choose or switch the agency workspace
//   POST /auth/password   { current, next }         (signed in)
//   POST /auth/sign-out
//   GET  /auth/me
//
// The database enforces lockout, session lifetime, replay and workspace checks (db/002_sign_in.sql).
// Passwords: scrypt. Authenticator secrets: the secret store. Session cookie: HttpOnly,
// SameSite=Strict, Secure over HTTPS; state-changing requests must also carry x-requested-with: ordix.
// Ported from the Health Company Platform's src/auth.ts.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { query, type DbConfig } from './db.ts';
import type { SecretStore } from './secrets.ts';

export interface Workspace { membershipId: string; agency: string; agencySlug: string; clientId: string | null; client: string | null; title: string; isOwner: boolean }
export interface SignedIn { personId: string; email: string; fullName: string; mustChangePassword: boolean; workspaces: Workspace[]; workspace: Workspace | null }

// ---------------------------------------------------------------------------
// Passwords and codes
// ---------------------------------------------------------------------------
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashPassword(pw: string): string {
  const salt = randomBytes(16);
  const h = scryptSync(pw, salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
export function verifyPassword(pw: string, stored: string): boolean {
  const [kind, n, r, p, salt, hash] = stored.split('$');
  if (kind !== 'scrypt') return false;
  const want = Buffer.from(hash, 'base64');
  const got = scryptSync(pw, Buffer.from(salt, 'base64'), want.length, { N: Number(n), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
  return got.length === want.length && timingSafeEqual(got, want);
}
export function passwordProblem(pw: string): string | null {
  if (pw.length < 12) return 'Use at least 12 characters';
  if (pw.length > 200) return 'Use at most 200 characters';
  if (/^(.)\1+$/.test(pw)) return 'Choose a less predictable password';
  return null;
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(buf: Buffer): string {
  let bits = 0, value = 0, out = '';
  for (const b of buf) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
export function fromBase32(s: string): Buffer {
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error('bad base32');
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

/** The 6-digit code for a 30-second step. */
export function totp(secret: Buffer, step: number, digits = 6): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac('sha1', secret).update(msg).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digits).padStart(digits, '0');
}
/** The step a code matches (now, or one step either side for clock drift), or null. */
export function matchTotp(secret: Buffer, code: string, at: Date): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const now = Math.floor(at.getTime() / 30000);
  for (const step of [now, now - 1, now + 1]) {
    if (timingSafeEqual(Buffer.from(totp(secret, step)), Buffer.from(code))) return step;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Sign-in routes and session lookup
// ---------------------------------------------------------------------------
export class AuthError extends Error { status: number; constructor(status: number, msg: string) { super(msg); this.status = status; } }

const COOKIE = 'ordix_session';
const WRITE_HEADER = 'ordix';
const sha = (t: string) => createHash('sha256').update(t).digest('hex');
const cookieToken = (req: IncomingMessage) => {
  const m = String(req.headers.cookie ?? '').match(new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]+)`));
  return m ? m[1] : '';
};
const ipOf = (req: IncomingMessage) => String(req.socket.remoteAddress ?? '').replace(/^::ffff:/, '');
const uaOf = (req: IncomingMessage) => String(req.headers['user-agent'] ?? '').slice(0, 400);
const dbError = (e: unknown, fallback: string) => {
  const m = String((e as { stderr?: string }).stderr ?? '').match(/ERROR:\s+(.*)/);
  return m ? m[1].trim() : fallback;
};

interface Challenge { personId: string; email: string; enrollSecret?: string; expires: number }

export function createAuth(o: { db: DbConfig; secrets: SecretStore; issuer?: string; secureCookies?: boolean; now?: () => Date }) {
  const now = o.now ?? (() => new Date());
  const challenges = new Map<string, Challenge>();
  const q = <T>(sql: string, vars: Record<string, string> = {}) => query<T>(o.db, sql, vars);
  const event = (email: string, personId: string | null, outcome: string, req: IncomingMessage) =>
    q(`INSERT INTO sign_in_events (email, person_id, outcome, ip, user_agent) VALUES (lower(:'e'), nullif(:'p', '')::uuid, :'o', nullif(:'ip', '')::inet, :'ua') RETURNING to_json(id);`,
      { e: email, p: personId ?? '', o: outcome, ip: ipOf(req), ua: uaOf(req) });

  async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
    let raw = '';
    for await (const c of req) { raw += c; if (raw.length > 1e5) throw new AuthError(413, 'Request too large'); }
    try { return raw ? JSON.parse(raw) : {}; } catch { throw new AuthError(400, 'Body must be JSON'); }
  }
  const text = (b: Record<string, unknown>, k: string) => (typeof b[k] === 'string' ? (b[k] as string) : '');

  /** The signed-in person, or null. Writes without the x-requested-with header count as signed out. */
  function current(req: IncomingMessage): SignedIn | null {
    const t = cookieToken(req);
    if (!t) return null;
    if (req.method !== 'GET' && req.headers['x-requested-with'] !== WRITE_HEADER) return null;
    return q<SignedIn | null>(`SELECT session_for(:'h');`, { h: sha(t) });
  }

  /** Requires a signed-in person working in a workspace; returns them and the membership to run requests as. */
  function require(req: IncomingMessage): SignedIn & { workspace: Workspace } {
    const s = current(req);
    if (!s) throw new AuthError(401, 'Sign in to continue');
    if (s.mustChangePassword) throw new AuthError(403, 'Choose a new password first');
    if (!s.workspace) throw new AuthError(409, 'Choose a workspace first');
    return s as SignedIn & { workspace: Workspace };
  }

  function newChallenge(c: Omit<Challenge, 'expires'>): string {
    for (const [k, v] of challenges) if (v.expires < Date.now()) challenges.delete(k);
    const id = randomBytes(24).toString('base64url');
    challenges.set(id, { ...c, expires: Date.now() + 5 * 60_000 });
    return id;
  }

  /** Handles /auth/*; returns false for any other path. */
  async function handle(req: IncomingMessage, res: ServerResponse, path: string): Promise<boolean> {
    if (!path.startsWith('/auth/')) return false;
    const send = (code: number, data: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers });
      res.end(JSON.stringify(data));
    };
    const cookie = (token: string, maxAge: number) =>
      `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${o.secureCookies ? '; Secure' : ''}`;
    try {
      if (path === '/auth/me' && req.method === 'GET') {
        const s = current(req);
        send(s ? 200 : 401, s ?? { error: 'Not signed in' });
        return true;
      }
      if (req.method !== 'POST') throw new AuthError(405, 'Method not allowed');
      if (req.headers['x-requested-with'] !== WRITE_HEADER) throw new AuthError(403, 'Missing request header');
      const b = await readBody(req);

      if (path === '/auth/sign-in') {
        const email = text(b, 'email').trim().toLowerCase();
        const row = q<{ id: string; enabled: boolean; locked: boolean; enrolled: boolean; hash: string } | null>(
          `SELECT json_build_object('id', p.id, 'enabled', s.enabled, 'locked', coalesce(s.locked_until > now(), false),
             'enrolled', s.mfa_enrolled_at IS NOT NULL, 'hash', s.password_hash)
           FROM people p JOIN person_sign_in s ON s.person_id = p.id WHERE p.email = :'e';`, { e: email });
        if (!row || !row.enabled) {
          event(email || '(blank)', row?.id ?? null, 'unknown_or_disabled', req);
          throw new AuthError(401, 'Email or password is incorrect');
        }
        if (row.locked) { event(email, row.id, 'locked', req); throw new AuthError(423, 'Too many attempts. Try again in 15 minutes.'); }
        if (!verifyPassword(text(b, 'password'), row.hash)) {
          const r = q<{ locked: boolean }>(`SELECT sign_in_failed(:'p', 'bad_password', :'ip', :'ua');`, { p: row.id, ip: ipOf(req), ua: uaOf(req) });
          throw new AuthError(r.locked ? 423 : 401, r.locked ? 'Too many attempts. Try again in 15 minutes.' : 'Email or password is incorrect');
        }
        if (row.enrolled) return send(200, { next: 'code', challenge: newChallenge({ personId: row.id, email }) }), true;
        const secret = base32(randomBytes(20));
        const issuer = o.issuer ?? 'Ordix';
        return send(200, { next: 'enroll', challenge: newChallenge({ personId: row.id, email, enrollSecret: secret }), secret,
          otpauth: `otpauth://totp/${encodeURIComponent(`${issuer}:${email}`)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30` }), true;
      }

      if (path === '/auth/verify') {
        const c = challenges.get(text(b, 'challenge'));
        if (!c || c.expires < Date.now()) throw new AuthError(401, 'That took too long. Sign in again.');
        const secretB32 = c.enrollSecret ?? (() => {
          const ref = q<string | null>(`SELECT to_json(totp_secret_ref) FROM person_sign_in WHERE person_id = :'p';`, { p: c.personId });
          if (!ref) throw new AuthError(401, 'Sign in again.');
          return o.secrets.get(ref);
        })();
        const step = matchTotp(fromBase32(secretB32), text(b, 'code').replace(/\s/g, ''), now());
        if (step === null) {
          const r = q<{ locked: boolean }>(`SELECT sign_in_failed(:'p', 'bad_code', :'ip', :'ua');`, { p: c.personId, ip: ipOf(req), ua: uaOf(req) });
          if (r.locked) challenges.delete(text(b, 'challenge'));
          throw new AuthError(r.locked ? 423 : 401, r.locked ? 'Too many attempts. Try again in 15 minutes.' : 'That code didn’t work. Use the newest code from your app.');
        }
        if (!q<boolean>(`SELECT to_json(use_totp_step(:'p', :'st'::bigint));`, { p: c.personId, st: String(step) })) {
          event(c.email, c.personId, 'code_reused', req);
          throw new AuthError(401, 'That code was already used. Wait for the next one.');
        }
        if (c.enrollSecret) {
          const ref = o.secrets.put(c.enrollSecret);
          q(`BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
            UPDATE person_sign_in SET totp_secret_ref = :'ref', mfa_enrolled_at = now() WHERE person_id = :'p' RETURNING to_json(person_id); COMMIT;`,
            { actor: c.email, ref, p: c.personId });
          event(c.email, c.personId, 'mfa_enrolled', req);
        }
        challenges.delete(text(b, 'challenge'));
        const token = randomBytes(32).toString('base64url');
        let who: unknown;
        try { who = q(`SELECT start_session(:'p', :'h', :'ip', :'ua');`, { p: c.personId, h: sha(token), ip: ipOf(req), ua: uaOf(req) }); }
        catch (e) { throw new AuthError(403, dbError(e, 'Sign-in refused')); }
        return send(200, who, { 'set-cookie': cookie(token, 43200) }), true;
      }

      if (path === '/auth/workspace') {
        const t = cookieToken(req);
        if (!t || !current(req)) throw new AuthError(401, 'Sign in to continue');
        try { return send(200, q(`SELECT choose_workspace(:'h', :'m'::uuid);`, { h: sha(t), m: text(b, 'membershipId') })), true; }
        catch (e) { throw new AuthError(403, dbError(e, 'That workspace is not available to you')); }
      }

      if (path === '/auth/password') {
        const s = current(req);
        if (!s) throw new AuthError(401, 'Sign in to continue');
        const hash = q<string>(`SELECT to_json(password_hash) FROM person_sign_in WHERE person_id = :'p';`, { p: s.personId });
        if (!verifyPassword(text(b, 'current'), hash)) throw new AuthError(401, 'Your current password is incorrect');
        const next = text(b, 'next');
        const problem = passwordProblem(next) ?? (next === text(b, 'current') ? 'Choose a different password' : null);
        if (problem) throw new AuthError(400, problem);
        q(`BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
          UPDATE person_sign_in SET password_hash = :'h', password_changed_at = now(), must_change_password = false
            WHERE person_id = :'p' RETURNING to_json(person_id); COMMIT;`, { actor: s.email, h: hashPassword(next), p: s.personId });
        event(s.email, s.personId, 'password_changed', req);
        return send(200, { ok: true }), true;
      }

      if (path === '/auth/sign-out') {
        const t = cookieToken(req);
        if (t) q(`SELECT end_session(:'h'); SELECT 'null'::json;`, { h: sha(t) });
        return send(200, { ok: true }, { 'set-cookie': cookie('', 0) }), true;
      }
      throw new AuthError(404, 'Not found');
    } catch (e) {
      const err = e instanceof AuthError ? e : new AuthError(500, 'Server error');
      send(err.status, { error: err.message });
      return true;
    }
  }

  return { handle, current, require };
}

/**
 * Gives a person a one-time temporary password (first invite, or a lost password).
 * They set up the authenticator and choose their own password at first sign-in.
 * resetMfa also clears the authenticator, for a lost phone. Ends their open sessions.
 */
export function issueTemporaryPassword(db: DbConfig, personId: string, opts: { resetMfa: boolean }, actor: string): { temporaryPassword: string } {
  const temporaryPassword = randomBytes(12).toString('base64url');
  query(db, `BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
    INSERT INTO person_sign_in (person_id, password_hash) VALUES (:'p'::uuid, :'h')
    ON CONFLICT (person_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, password_changed_at = now(),
      must_change_password = true, failed_attempts = 0, locked_until = NULL,
      totp_secret_ref = CASE WHEN :'mfa'::boolean THEN NULL ELSE person_sign_in.totp_secret_ref END,
      mfa_enrolled_at = CASE WHEN :'mfa'::boolean THEN NULL ELSE person_sign_in.mfa_enrolled_at END,
      last_totp_step  = CASE WHEN :'mfa'::boolean THEN NULL ELSE person_sign_in.last_totp_step END;
    UPDATE sessions SET ended_at = now() WHERE person_id = :'p'::uuid AND ended_at IS NULL;
    SELECT 'null'::json; COMMIT;`, { actor, p: personId, h: hashPassword(temporaryPassword), mfa: String(opts.resetMfa) });
  return { temporaryPassword };
}
