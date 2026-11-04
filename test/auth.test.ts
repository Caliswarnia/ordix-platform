// Sign-in: password + authenticator code, lockout, replay, sessions and workspaces.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuth, issueTemporaryPassword, totp, fromBase32, matchTotp, AuthError } from '../src/auth.ts';
import { LocalEncryptedStore } from '../src/secrets.ts';
import { createAgency, addClient, addMember } from '../src/access.ts';
import { query, asMember } from '../src/db.ts';
import { freshDb, psql } from './helpers.ts';

const { cfg, drop } = freshDb('auth');
let server: Server, base = '';
const secrets: Record<string, string> = {};
const passwords: Record<string, string> = {};
let a: { agencyId: string; ownerMembershipId: string }, b: { agencyId: string; ownerMembershipId: string };
let sharedInA = '', sharedInB = '', dental = '';

function client() {
  let cookie = '';
  return {
    async call(method: string, path: string, body?: unknown, headers: Record<string, string> = { 'x-requested-with': 'ordix' }) {
      const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', cookie, ...headers }, body: body ? JSON.stringify(body) : undefined });
      const set = r.headers.get('set-cookie');
      if (set) cookie = set.split(';')[0];
      return { status: r.status, data: await r.json().catch(() => null) as any };
    },
    get cookie() { return cookie; },
  };
}
const codeFor = (secret: string, offset = 0) => totp(fromBase32(secret), Math.floor(Date.now() / 30000) + offset);
const clearReplay = (email: string) => psql(cfg, `UPDATE person_sign_in SET last_totp_step = NULL WHERE person_id = (SELECT id FROM people WHERE email = '${email}');`);
const personId = (email: string) => query<string>(cfg, `SELECT to_json(id) FROM people WHERE email = '${email}';`);

async function signIn(email: string, password = passwords[email]) {
  const c = client();
  const r = await c.call('POST', '/auth/sign-in', { email, password });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  if (r.data.next === 'enroll') secrets[email] = r.data.secret;
  clearReplay(email);
  const v = await c.call('POST', '/auth/verify', { challenge: r.data.challenge, code: codeFor(secrets[email]) });
  return { c, v };
}

before(async () => {
  a = createAgency(cfg, { name: 'Brightline Digital', slug: 'brightline', ownerEmail: 'dana@brightline.example', ownerName: 'Dana Ortiz' }, 'ordix:test');
  b = createAgency(cfg, { name: 'Copperline Marketing', slug: 'copperline', ownerEmail: 'kim@copperline.example', ownerName: 'Kim Lee' }, 'ordix:test');
  dental = addClient(cfg, a.ownerMembershipId, 'dana@brightline.example', { name: 'Desert Smiles Dental' });
  addClient(cfg, b.ownerMembershipId, 'kim@copperline.example', { name: 'Copperline Client' });
  // A freelancer who works for both agencies.
  sharedInA = addMember(cfg, a.ownerMembershipId, 'dana@brightline.example', { email: 'sam@freelance.example', fullName: 'Sam Patel', template: 'seo_specialist' });
  sharedInB = addMember(cfg, b.ownerMembershipId, 'kim@copperline.example', { email: 'sam@freelance.example', fullName: 'Sam Patel', template: 'media_buyer' });
  addMember(cfg, a.ownerMembershipId, 'dana@brightline.example', { email: 'lena@desertsmiles.example', fullName: 'Lena Ruiz', template: 'client_admin', clientId: dental });
  for (const e of ['dana@brightline.example', 'sam@freelance.example', 'lena@desertsmiles.example'])
    passwords[e] = issueTemporaryPassword(cfg, personId(e), { resetMfa: false }, 'ordix:test').temporaryPassword;

  const auth = createAuth({ db: cfg, secrets: new LocalEncryptedStore(join(mkdtempSync(join(tmpdir(), 'ordix-')), 's.json'), 'e'.repeat(64)) });
  server = createServer(async (req, res) => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    if (await auth.handle(req, res, path)) return;
    try {
      const s = auth.require(req);
      const clients = asMember(cfg, s.workspace.membershipId, s.email, `SELECT coalesce(json_agg(name ORDER BY name), '[]') FROM clients;`);
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ agency: s.workspace.agency, clients }));
    } catch (e) {
      const err = e instanceof AuthError ? e : new AuthError(500, 'Server error');
      res.writeHead(err.status, { 'content-type': 'application/json' }).end(JSON.stringify({ error: err.message }));
    }
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); drop(); });

test('authenticator codes match the RFC 6238 test vector', () => {
  const secret = Buffer.from('12345678901234567890');
  assert.equal(totp(secret, Math.floor(59 / 30), 8), '94287082');
  assert.equal(totp(secret, Math.floor(1111111109 / 30), 8), '07081804');
  assert.equal(matchTotp(secret, totp(secret, 1000), new Date(1003 * 30000)), null, 'too old');
});

test('first sign-in sets up the authenticator, then requires a new password', async () => {
  const email = 'dana@brightline.example';
  const c = client();
  const r = await c.call('POST', '/auth/sign-in', { email: 'DANA@Brightline.example', password: passwords[email] });
  assert.equal(r.data.next, 'enroll');
  assert.match(r.data.otpauth, /^otpauth:\/\/totp\/Ordix%3Adana%40brightline\.example\?secret=[A-Z2-7]+&issuer=Ordix/);
  secrets[email] = r.data.secret;
  assert.equal((await c.call('POST', '/auth/verify', { challenge: r.data.challenge, code: '000000' })).status, 401);
  const v = await c.call('POST', '/auth/verify', { challenge: r.data.challenge, code: codeFor(r.data.secret) });
  assert.equal(v.status, 200, JSON.stringify(v.data));
  assert.equal(v.data.workspace.agency, 'Brightline Digital', 'one workspace is chosen automatically');
  assert.equal((await c.call('GET', '/api/clients')).status, 403, 'temporary password must be replaced first');
  assert.equal((await c.call('POST', '/auth/password', { current: passwords[email], next: 'short' })).status, 400);
  assert.equal((await c.call('POST', '/auth/password', { current: passwords[email], next: 'a-much-better-passphrase' })).status, 200);
  passwords[email] = 'a-much-better-passphrase';
  const api = await c.call('GET', '/api/clients');
  assert.deepEqual(api.data, { agency: 'Brightline Digital', clients: ['Desert Smiles Dental'] });
});

test('the second sign-in asks only for the code, and a code works once', async () => {
  const email = 'dana@brightline.example';
  const c = client();
  const r = await c.call('POST', '/auth/sign-in', { email, password: passwords[email] });
  assert.equal(r.data.next, 'code');
  clearReplay(email);
  const code = codeFor(secrets[email]);
  assert.equal((await c.call('POST', '/auth/verify', { challenge: r.data.challenge, code })).status, 200);
  const again = await client().call('POST', '/auth/sign-in', { email, password: passwords[email] });
  const reuse = await client().call('POST', '/auth/verify', { challenge: again.data.challenge, code });
  assert.equal(reuse.status, 401);
  assert.match(reuse.data.error, /already used/);
});

test('someone in two agencies picks a workspace, and sees only that agency’s data', async () => {
  const email = 'sam@freelance.example';
  const { c, v } = await signIn(email);
  assert.equal(v.status, 200);
  assert.equal(v.data.workspaces.length, 2);
  assert.equal(v.data.workspace, null);
  await c.call('POST', '/auth/password', { current: passwords[email], next: 'freelancer-passphrase-1' });
  passwords[email] = 'freelancer-passphrase-1';
  assert.equal((await c.call('GET', '/api/clients')).status, 409, 'must choose a workspace');
  await c.call('POST', '/auth/workspace', { membershipId: sharedInA });
  assert.deepEqual((await c.call('GET', '/api/clients')).data.clients, ['Desert Smiles Dental']);
  await c.call('POST', '/auth/workspace', { membershipId: sharedInB });
  assert.deepEqual((await c.call('GET', '/api/clients')).data, { agency: 'Copperline Marketing', clients: ['Copperline Client'] });
  const other = await c.call('POST', '/auth/workspace', { membershipId: a.ownerMembershipId });
  assert.equal(other.status, 403, 'cannot pick someone else’s membership');
});

test('deactivating a membership removes that workspace at once', async () => {
  const { c } = await signIn('sam@freelance.example');
  await c.call('POST', '/auth/workspace', { membershipId: sharedInB });
  asMember(cfg, b.ownerMembershipId, 'kim@copperline.example', `UPDATE memberships SET active = false WHERE id = :'m'::uuid; SELECT 'null'::json;`, { m: sharedInB });
  assert.equal((await c.call('GET', '/api/clients')).status, 409);
  const me = await c.call('GET', '/auth/me');
  assert.equal(me.data.workspaces.length, 1);
});

test('a client admin signs in straight to their own client', async () => {
  const email = 'lena@desertsmiles.example';
  const { c } = await signIn(email);
  await c.call('POST', '/auth/password', { current: passwords[email], next: 'client-admin-passphrase' });
  assert.deepEqual((await c.call('GET', '/api/clients')).data.clients, ['Desert Smiles Dental']);
});

test('five wrong passwords lock sign-in for 15 minutes', async () => {
  const email = 'lena@desertsmiles.example';
  for (let i = 0; i < 4; i++) assert.equal((await client().call('POST', '/auth/sign-in', { email, password: 'wrong-wrong-wrong' })).status, 401);
  assert.equal((await client().call('POST', '/auth/sign-in', { email, password: 'wrong-wrong-wrong' })).status, 423);
  assert.equal((await client().call('POST', '/auth/sign-in', { email, password: 'client-admin-passphrase' })).status, 423, 'locked even with the right password');
  psql(cfg, `UPDATE person_sign_in SET locked_until = NULL WHERE person_id = '${personId(email)}';`);
});

test('writes without the request header are refused, and sign-out ends the session', async () => {
  const { c } = await signIn('dana@brightline.example');
  assert.equal((await c.call('POST', '/auth/sign-out', {}, {})).status, 403);
  assert.equal((await c.call('POST', '/auth/sign-out', {})).status, 200);
  assert.equal((await c.call('GET', '/auth/me')).status, 401);
});

test('sessions end after 30 idle minutes and when sign-in is turned off', async () => {
  const { c } = await signIn('dana@brightline.example');
  psql(cfg, `UPDATE sessions SET last_seen_at = now() - interval '31 minutes' WHERE ended_at IS NULL AND person_id = '${personId('dana@brightline.example')}';`);
  assert.equal((await c.call('GET', '/auth/me')).status, 401);
  const { c: c2 } = await signIn('dana@brightline.example');
  psql(cfg, `UPDATE person_sign_in SET enabled = false WHERE person_id = '${personId('dana@brightline.example')}';`);
  assert.equal((await c2.call('GET', '/auth/me')).status, 401);
  psql(cfg, `UPDATE person_sign_in SET enabled = true WHERE person_id = '${personId('dana@brightline.example')}';`);
});

test('every attempt is kept, the log can’t be changed, and members can’t read sign-in data', () => {
  const outcomes = query<string[]>(cfg, `SELECT json_agg(DISTINCT outcome) FROM sign_in_events;`);
  for (const o of ['signed_in', 'bad_password', 'bad_code', 'code_reused', 'locked', 'mfa_enrolled', 'password_changed', 'workspace_chosen', 'signed_out'])
    assert.ok(outcomes.includes(o), `missing ${o}`);
  assert.throws(() => psql(cfg, `DELETE FROM sign_in_events;`));
  assert.throws(() => asMember(cfg, a.ownerMembershipId, 'dana@brightline.example', `SELECT count(*) FROM person_sign_in;`));
  const audit = query<string>(cfg, `SELECT to_json(string_agg(after::text, '')) FROM audit_log WHERE entity = 'person_sign_in';`);
  assert.ok(!audit.includes('scrypt$'), 'password hashes never reach the audit log');
});
