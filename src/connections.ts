// Connected accounts: starting a provider sign-in (Google or Meta), finishing it, keeping tokens usable,
// reading dashboard data and disconnecting. Tokens and app secrets live only in the secret store.
import { createHash, randomBytes } from 'node:crypto';
import { query, asMember, type DbConfig } from './db.ts';
import type { SecretStore } from './secrets.ts';
import { authUrl, GoogleError, type Google } from './google.ts';
import { metaAuthUrl, MetaError, type Meta } from './meta.ts';
import { AuthError, type SignedIn, type Workspace } from './auth.ts';

type Member = SignedIn & { workspace: Workspace };
export type Provider = 'google' | 'meta';
const NAMES: Record<Provider, string> = { google: 'Google', meta: 'Meta' };
const sha = (t: string) => createHash('sha256').update(t).digest('hex');
const day = (d: Date) => d.toISOString().slice(0, 10);
const addDays = (d: Date, n: number) => new Date(d.getTime() + n * 86400000);
const dbMessage = (e: unknown, fallback: string) => {
  const m = String((e as { stderr?: string }).stderr ?? '').match(/ERROR:\s+(.*)/);
  return m ? m[1].trim() : fallback;
};
const providerError = (e: unknown) => e instanceof GoogleError || e instanceof MetaError;

export interface ConnectionsConfig {
  db: DbConfig;
  secrets: SecretStore;
  google: Google;
  meta: Meta;
  /** Ordix's own OAuth apps, used unless the agency brings its own. */
  googleApp?: { clientId: string; clientSecret: string };
  metaApp?: { clientId: string; clientSecret: string };
  publicUrl: string;   // e.g. https://app.ordixit.com
  now?: () => Date;
}

export function createConnections(o: ConnectionsConfig) {
  const now = o.now ?? (() => new Date());
  const q = <T>(sql: string, vars: Record<string, string> = {}) => query<T>(o.db, sql, vars);
  const redirectUri = (p: Provider) => `${o.publicUrl.replace(/\/$/, '')}/oauth/${p}/callback`;
  const tokens = new Map<string, { token: string; until: number }>();
  const cache = new Map<string, { data: unknown; until: number }>();

  /** The agency's own app for a provider if it has one, else Ordix's. */
  function appFor(agencyId: string, p: Provider) {
    const own = q<{ clientId: string; secretRef: string } | null>(
      `SELECT json_build_object('clientId', app_client_id, 'secretRef', secret_ref) FROM oauth_apps WHERE agency_id = :'a'::uuid AND provider = :'p';`, { a: agencyId, p });
    if (own) return { clientId: own.clientId, clientSecret: o.secrets.get(own.secretRef), redirectUri: redirectUri(p), viaAgency: true };
    const ours = p === 'google' ? o.googleApp : o.metaApp;
    if (!ours) throw new AuthError(503, `${NAMES[p]} connections aren’t set up yet`);
    return { ...ours, redirectUri: redirectUri(p), viaAgency: false };
  }

  function markReconnect(connectionId: string) {
    q(`BEGIN; SELECT set_config('app.actor', 'system:token-check', true) \\g /dev/null
      UPDATE connections SET status = 'needs_reconnect' WHERE id = :'c'::uuid AND status = 'connected'; SELECT 'null'::json; COMMIT;`, { c: connectionId });
  }

  /** Step 1: a signed-in member asks to connect a client's account; returns where to send their browser. */
  function start(m: Member, clientId: string, p: Provider): string {
    const state = randomBytes(24).toString('base64url');
    try { asMember(o.db, m.workspace.membershipId, m.email, `SELECT begin_connection(:'c'::uuid, :'p', :'s'); SELECT 'null'::json;`, { c: clientId, p, s: sha(state) }); }
    catch (e) { throw new AuthError(403, dbMessage(e, 'You can’t connect accounts for this client')); }
    const agencyId = q<string>(`SELECT to_json(agency_id) FROM memberships WHERE id = :'m'::uuid;`, { m: m.workspace.membershipId });
    const app = appFor(agencyId, p);
    return p === 'google' ? authUrl(app, state) : metaAuthUrl(app, state, o.meta.version);
  }

  /** Step 2: the provider sends the browser back. Returns the client id to show. */
  async function finish(p: Provider, signedIn: SignedIn | null, params: URLSearchParams): Promise<string> {
    let s: { membershipId: string; clientId: string; agencyId: string; personId: string; provider: Provider };
    try { s = q(`SELECT consume_oauth_state(:'s');`, { s: sha(params.get('state') ?? '') }); }
    catch (e) { throw new AuthError(400, dbMessage(e, 'This sign-in link has expired. Start again.')); }
    if (s.provider !== p) throw new AuthError(400, 'This sign-in link is for a different service. Start again.');
    // The browser coming back must belong to the person who started, so a link can't be replayed into someone else's session.
    if (!signedIn || signedIn.personId !== s.personId) throw new AuthError(403, 'Sign in as the person who started connecting, then try again.');
    if (params.get('error')) throw new AuthError(400, /denied/.test(params.get('error') ?? '') ? `${NAMES[p]} access wasn’t granted.` : `${NAMES[p]} didn’t complete the sign-in.`);
    const app = appFor(s.agencyId, p);
    const code = params.get('code') ?? '';

    let secret: string, access: string, ttl: number, email: string | null, scopes: string[], expiresAt: string | null = null;
    try {
      if (p === 'google') {
        const t = await o.google.exchangeCode(app, code);
        secret = JSON.stringify({ refreshToken: t.refreshToken }); access = t.accessToken; ttl = t.expiresIn; email = t.email; scopes = t.scopes;
      } else {
        const t = await o.meta.exchangeCode(app, code);
        expiresAt = new Date(now().getTime() + t.expiresIn * 1000).toISOString();
        secret = JSON.stringify({ accessToken: t.accessToken, expiresAt }); access = t.accessToken; ttl = t.expiresIn; email = t.email; scopes = t.scopes;
      }
    } catch (e) { throw new AuthError(400, (e as Error).message); }

    const tokenRef = o.secrets.put(secret);
    let connectionId: string;
    try {
      connectionId = q<string>(`BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
        INSERT INTO connections (agency_id, client_id, provider, account_email, scopes, token_ref, via_agency_app, connected_by, token_expires_at)
          VALUES (:'a'::uuid, :'c'::uuid, :'p', nullif(:'email', ''), string_to_array(nullif(:'scopes', ''), ' '), :'ref', :'via'::boolean, :'actor', nullif(:'exp', '')::timestamptz)
          RETURNING to_json(id); COMMIT;`,
        { actor: signedIn.email, a: s.agencyId, c: s.clientId, p, email: email ?? '', scopes: scopes.join(' '), ref: tokenRef, via: String(app.viaAgency), exp: expiresAt ?? '' });
    } catch (e) { o.secrets.delete(tokenRef); throw e; }
    tokens.set(connectionId, { token: access, until: Date.now() + Math.min(ttl - 120, 3600) * 1000 });

    const rows = p === 'google'
      ? (await Promise.all([o.google.searchConsoleSites(access).catch(() => []), o.google.analyticsProperties(access).catch(() => [])]))
          .flatMap((list, i) => list.map(x => ({ ...x, kind: i === 0 ? 'search_console_site' : 'ga4_property' })))
      : (await Promise.all([o.meta.adAccounts(access).catch(() => []), o.meta.pages(access).catch(() => [])]))
          .flatMap((list, i) => list.map(x => ({ ...x, kind: i === 0 ? 'meta_ad_account' : 'meta_page' })));
    if (rows.length) {
      q(`BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
        INSERT INTO connection_properties (connection_id, agency_id, client_id, kind, external_id, label)
          SELECT :'conn'::uuid, :'a'::uuid, :'c'::uuid, r->>'kind', r->>'id', r->>'label' FROM jsonb_array_elements(:'rows'::jsonb) r
          ON CONFLICT DO NOTHING;
        -- When exactly one of a kind came back and the client has none selected yet, select it.
        UPDATE connection_properties p SET selected = true WHERE p.connection_id = :'conn'::uuid
          AND (SELECT count(*) FROM connection_properties x WHERE x.connection_id = p.connection_id AND x.kind = p.kind) = 1
          AND NOT EXISTS (SELECT 1 FROM connection_properties y WHERE y.client_id = p.client_id AND y.kind = p.kind AND y.selected);
        SELECT 'null'::json; COMMIT;`, { actor: signedIn.email, conn: connectionId, a: s.agencyId, c: s.clientId, rows: JSON.stringify(rows) });
    }
    cache.clear();
    return s.clientId;
  }

  /** A usable access token. Google: refreshed when needed. Meta: the long-lived token until it expires. */
  async function accessToken(connectionId: string): Promise<string> {
    const hit = tokens.get(connectionId);
    if (hit && hit.until > Date.now()) return hit.token;
    const c = q<{ ref: string | null; agencyId: string; status: string; provider: Provider } | null>(
      `SELECT json_build_object('ref', token_ref, 'agencyId', agency_id, 'status', status, 'provider', provider) FROM connections WHERE id = :'c'::uuid;`, { c: connectionId });
    if (!c || !c.ref || c.status !== 'connected') throw new AuthError(409, 'Reconnect this account');
    const stored = JSON.parse(o.secrets.get(c.ref));
    if (c.provider === 'meta') {
      if (Date.parse(stored.expiresAt) <= now().getTime()) { markReconnect(connectionId); throw new MetaError(401, 'Meta sign-in expired. Reconnect the account.', true); }
      tokens.set(connectionId, { token: stored.accessToken, until: Math.min(Date.parse(stored.expiresAt), Date.now() + 3600_000) });
      return stored.accessToken;
    }
    try {
      const r = await o.google.refresh(appFor(c.agencyId, 'google'), stored.refreshToken);
      tokens.set(connectionId, { token: r.accessToken, until: Date.now() + (r.expiresIn - 120) * 1000 });
      return r.accessToken;
    } catch (e) {
      if (e instanceof GoogleError && e.reconnect) markReconnect(connectionId);
      throw e;
    }
  }

  /** Connections and properties a member can see for a client. */
  function list(m: Member, clientId: string) {
    return asMember(o.db, m.workspace.membershipId, m.email, `
      SELECT coalesce(json_agg(json_build_object('id', c.id, 'provider', c.provider, 'account', c.account_email, 'status', c.status,
        'connectedBy', c.connected_by, 'connectedAt', c.connected_at, 'agencyApp', c.via_agency_app, 'expiresAt', c.token_expires_at,
        'properties', (SELECT coalesce(json_agg(json_build_object('id', p.id, 'kind', p.kind, 'label', p.label, 'selected', p.selected) ORDER BY p.kind, p.label), '[]')
                       FROM connection_properties p WHERE p.connection_id = c.id)) ORDER BY c.provider, c.connected_at DESC), '[]')
      FROM connections c WHERE c.client_id = :'c'::uuid AND c.status <> 'disconnected';`, { c: clientId });
  }

  function selectProperty(m: Member, propertyId: string): void {
    try { asMember(o.db, m.workspace.membershipId, m.email, `SELECT select_property(:'p'::uuid); SELECT 'null'::json;`, { p: propertyId }); }
    catch (e) { throw new AuthError(403, dbMessage(e, 'You can’t change this')); }
    cache.clear();
  }

  async function disconnect(m: Member, connectionId: string): Promise<void> {
    const provider = q<Provider | null>(`SELECT to_json(provider) FROM connections WHERE id = :'c'::uuid;`, { c: connectionId });
    let ref: string | null;
    try { ref = asMember<string | null>(o.db, m.workspace.membershipId, m.email, `SELECT to_json(disconnect_connection(:'c'::uuid));`, { c: connectionId }); }
    catch (e) { throw new AuthError(/not found/i.test(dbMessage(e, '')) ? 404 : 403, dbMessage(e, 'You can’t disconnect this account')); }
    tokens.delete(connectionId); cache.clear();
    if (!ref) return;
    try {
      const stored = JSON.parse(o.secrets.get(ref));
      if (provider === 'meta') await o.meta.revoke(stored.accessToken); else await o.google.revoke(stored.refreshToken);
    } catch { /* the token is deleted either way */ }
    o.secrets.delete(ref);
  }

  /** The selected property of a kind for a client (any status but disconnected). */
  function selected(clientId: string, kinds: string[]) {
    return q<{ kind: string; ext: string; label: string; conn: string; status: string }[]>(`
      SELECT coalesce(json_agg(json_build_object('kind', p.kind, 'ext', p.external_id, 'label', p.label, 'conn', c.id, 'status', c.status)), '[]')
      FROM connection_properties p JOIN connections c ON c.id = p.connection_id
      WHERE p.client_id = :'c'::uuid AND p.selected AND c.status <> 'disconnected' AND p.kind = ANY (string_to_array(:'k', ','));`, { c: clientId, k: kinds.join(',') });
  }
  function allowed(m: Member, clientId: string, area: string) {
    const ok = asMember<boolean>(o.db, m.workspace.membershipId, m.email, `SELECT to_json(can_reach_client(:'c'::uuid) AND current_can(:'a', 'view'));`, { c: clientId, a: area });
    if (!ok) throw new AuthError(403, 'Your role doesn’t include this area for this client');
  }
  async function cached<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const hit = cache.get(key);
    if (hit && hit.until > Date.now()) return hit.data as T;
    const data = await fn();
    cache.set(key, { data, until: Date.now() + 30 * 60_000 });
    return data;
  }

  /** The SEO tab: Search Console clicks by week, totals, top queries and pages, plus Analytics totals. */
  async function seo(m: Member, clientId: string) {
    allowed(m, clientId, 'seo');
    const sel = selected(clientId, ['search_console_site', 'ga4_property']);
    const site = sel.find(x => x.kind === 'search_console_site'), ga = sel.find(x => x.kind === 'ga4_property');
    if (!site && !ga) return { connected: false };
    try {
      return await cached(`seo|${clientId}|${site?.ext}|${ga?.ext}`, async () => {
        const end = addDays(now(), -3);            // Search Console data settles after about 3 days
        const out: Record<string, unknown> = { connected: true, site: site?.label ?? null, property: ga?.label ?? null, through: day(end) };
        if (site) {
          if (site.status !== 'connected') throw new GoogleError(409, 'Reconnect this Google account', true);
          const token = await accessToken(site.conn);
          const range = (from: number, to: number) => ({ startDate: day(addDays(end, from)), endDate: day(addDays(end, to)) });
          const [daily, queries, pages] = await Promise.all([
            o.google.searchAnalytics(token, site.ext, { ...range(-83, 0), dimensions: ['date'], rowLimit: 100 }),
            o.google.searchAnalytics(token, site.ext, { ...range(-27, 0), dimensions: ['query'], rowLimit: 10 }),
            o.google.searchAnalytics(token, site.ext, { ...range(-27, 0), dimensions: ['page'], rowLimit: 10 }),
          ]);
          const weeks = Array.from({ length: 12 }, (_, i) => ({ weekEnding: day(addDays(end, -7 * (11 - i))), clicks: 0, impressions: 0 }));
          for (const r of daily) {
            const back = Math.floor((Date.parse(day(end)) - Date.parse(r.keys[0])) / 86400000 / 7);
            const w = weeks[11 - back];
            if (w) { w.clicks += r.clicks; w.impressions += r.impressions; }
          }
          const inRange = (from: number, to: number) => daily.filter(r => { const d = Date.parse(r.keys[0]); return d >= Date.parse(day(addDays(end, from))) && d <= Date.parse(day(addDays(end, to))); });
          const cur = inRange(-27, 0), prev = inRange(-55, -28);
          const impressions = cur.reduce((a, r) => a + r.impressions, 0);
          out.weeks = weeks;
          out.totals = { clicks: cur.reduce((a, r) => a + r.clicks, 0), clicksPrev: prev.reduce((a, r) => a + r.clicks, 0), impressions,
            position: impressions ? cur.reduce((a, r) => a + r.position * r.impressions, 0) / impressions : null };
          out.queries = queries.map(r => ({ query: r.keys[0], clicks: r.clicks, impressions: r.impressions, position: r.position }));
          out.pages = pages.map(r => ({ page: r.keys[0], clicks: r.clicks, impressions: r.impressions, position: r.position }));
        }
        if (ga) {
          if (ga.status !== 'connected') throw new GoogleError(409, 'Reconnect this Google account', true);
          out.analytics = await o.google.analyticsTotals(await accessToken(ga.conn), ga.ext, day(addDays(end, -27)), day(end));
        }
        return out;
      });
    } catch (e) {
      if (providerError(e)) return { connected: true, error: (e as Error).message, reconnect: (e as GoogleError).reconnect };
      throw e;
    }
  }

  /** The Paid media tab: Meta ad spend by week, totals and top campaigns for the selected ad account. */
  async function ads(m: Member, clientId: string) {
    allowed(m, clientId, 'ads');
    const acct = selected(clientId, ['meta_ad_account'])[0];
    if (!acct) return { connected: false };
    try {
      return await cached(`ads|${clientId}|${acct.ext}`, async () => {
        if (acct.status !== 'connected') throw new MetaError(409, 'Reconnect this Meta account', true);
        const token = await accessToken(acct.conn);
        const until = day(addDays(now(), -1));
        const r = await o.meta.adReport(token, acct.ext, day(addDays(now(), -84)), until, day(addDays(now(), -56)), day(addDays(now(), -29)));
        return { connected: true, account: acct.label, through: until, ...r };
      });
    } catch (e) {
      if (providerError(e)) return { connected: true, account: acct.label, error: (e as Error).message, reconnect: (e as MetaError).reconnect };
      throw e;
    }
  }

  /** Agency owners can bring their own OAuth app; the secret goes to the secret store. */
  function saveAgencyApp(m: Member, provider: Provider, appClientId: string, appSecret: string): void {
    const isOwner = asMember<boolean>(o.db, m.workspace.membershipId, m.email, `SELECT to_json(coalesce((current_membership()).is_owner, false));`);
    if (!isOwner) throw new AuthError(403, 'Only the agency owner can change API keys');
    if (!appClientId.trim() || appSecret.trim().length < 8) throw new AuthError(400, 'Enter the client ID and client secret');
    const agencyId = q<string>(`SELECT to_json(agency_id) FROM memberships WHERE id = :'m'::uuid;`, { m: m.workspace.membershipId });
    const ref = o.secrets.put(appSecret.trim());
    const old = q<string | null>(`SELECT to_json(secret_ref) FROM oauth_apps WHERE agency_id = :'a'::uuid AND provider = :'p';`, { a: agencyId, p: provider });
    q(`BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
      INSERT INTO oauth_apps (agency_id, provider, app_client_id, secret_ref) VALUES (:'a'::uuid, :'p', :'cid', :'ref')
      ON CONFLICT (agency_id, provider) DO UPDATE SET app_client_id = EXCLUDED.app_client_id, secret_ref = EXCLUDED.secret_ref;
      SELECT 'null'::json; COMMIT;`, { actor: m.email, a: agencyId, p: provider, cid: appClientId.trim(), ref });
    if (old) o.secrets.delete(old);
  }

  return { start, finish, list, selectProperty, disconnect, seo, ads, saveAgencyApp, accessToken };
}
export type Connections = ReturnType<typeof createConnections>;
