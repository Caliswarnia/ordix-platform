// Connected accounts: starting the Google sign-in, finishing it, keeping tokens fresh, reading
// dashboard data and disconnecting. Tokens and app secrets live only in the secret store.
import { createHash, randomBytes } from 'node:crypto';
import { query, asMember, type DbConfig } from './db.ts';
import type { SecretStore } from './secrets.ts';
import { authUrl, GoogleError, type Google, type GoogleApp } from './google.ts';
import { AuthError, type SignedIn, type Workspace } from './auth.ts';

type Member = SignedIn & { workspace: Workspace };
const sha = (t: string) => createHash('sha256').update(t).digest('hex');
const day = (d: Date) => d.toISOString().slice(0, 10);
const addDays = (d: Date, n: number) => new Date(d.getTime() + n * 86400000);
const dbMessage = (e: unknown, fallback: string) => {
  const m = String((e as { stderr?: string }).stderr ?? '').match(/ERROR:\s+(.*)/);
  return m ? m[1].trim() : fallback;
};

export interface ConnectionsConfig {
  db: DbConfig;
  secrets: SecretStore;
  google: Google;
  /** Ordix's own Google OAuth app, used unless the agency brings its own. */
  googleApp?: { clientId: string; clientSecret: string };
  publicUrl: string;   // e.g. https://app.ordixit.com
  now?: () => Date;
}

export function createConnections(o: ConnectionsConfig) {
  const now = o.now ?? (() => new Date());
  const q = <T>(sql: string, vars: Record<string, string> = {}) => query<T>(o.db, sql, vars);
  const redirectUri = `${o.publicUrl.replace(/\/$/, '')}/oauth/google/callback`;
  const tokens = new Map<string, { token: string; until: number }>();
  const cache = new Map<string, { data: unknown; until: number }>();

  /** The agency's own Google app if it has one, else Ordix's. */
  function googleAppFor(agencyId: string): GoogleApp & { viaAgency: boolean } {
    const own = q<{ clientId: string; secretRef: string } | null>(
      `SELECT json_build_object('clientId', app_client_id, 'secretRef', secret_ref) FROM oauth_apps WHERE agency_id = :'a'::uuid AND provider = 'google';`, { a: agencyId });
    if (own) return { clientId: own.clientId, clientSecret: o.secrets.get(own.secretRef), redirectUri, viaAgency: true };
    if (!o.googleApp) throw new AuthError(503, 'Google connections aren’t set up yet');
    return { ...o.googleApp, redirectUri, viaAgency: false };
  }

  /** Step 1: a signed-in member asks to connect a client's Google account; returns where to send their browser. */
  function startGoogle(m: Member, clientId: string): string {
    const state = randomBytes(24).toString('base64url');
    try { asMember(o.db, m.workspace.membershipId, m.email, `SELECT begin_connection(:'c'::uuid, 'google', :'s'); SELECT 'null'::json;`, { c: clientId, s: sha(state) }); }
    catch (e) { throw new AuthError(403, dbMessage(e, 'You can’t connect accounts for this client')); }
    const agencyId = q<string>(`SELECT to_json(agency_id) FROM memberships WHERE id = :'m'::uuid;`, { m: m.workspace.membershipId });
    return authUrl(googleAppFor(agencyId), state);
  }

  /** Step 2: Google sends the browser back. Returns the client id to show. */
  async function finishGoogle(signedIn: SignedIn | null, params: URLSearchParams): Promise<string> {
    const state = params.get('state') ?? '';
    let s: { membershipId: string; clientId: string; agencyId: string; personId: string };
    try { s = q(`SELECT consume_oauth_state(:'s');`, { s: sha(state) }); }
    catch (e) { throw new AuthError(400, dbMessage(e, 'This sign-in link has expired. Start again.')); }
    // The browser coming back must belong to the person who started, so a link can't be replayed into someone else's session.
    if (!signedIn || signedIn.personId !== s.personId) throw new AuthError(403, 'Sign in as the person who started connecting, then try again.');
    if (params.get('error')) throw new AuthError(400, params.get('error') === 'access_denied' ? 'Google access wasn’t granted.' : 'Google didn’t complete the sign-in.');
    const app = googleAppFor(s.agencyId);
    const t = await o.google.exchangeCode(app, params.get('code') ?? '').catch((e: Error) => { throw new AuthError(400, e.message); });
    const tokenRef = o.secrets.put(JSON.stringify({ refreshToken: t.refreshToken }));
    let connectionId: string;
    try {
      connectionId = q<string>(`BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
        INSERT INTO connections (agency_id, client_id, provider, account_email, scopes, token_ref, via_agency_app, connected_by)
          VALUES (:'a'::uuid, :'c'::uuid, 'google', nullif(:'email', ''), string_to_array(:'scopes', ' '), :'ref', :'via'::boolean, :'actor')
          RETURNING to_json(id); COMMIT;`,
        { actor: signedIn.email, a: s.agencyId, c: s.clientId, email: t.email ?? '', scopes: t.scopes.join(' '), ref: tokenRef, via: String(app.viaAgency) });
    } catch (e) { o.secrets.delete(tokenRef); throw e; }
    tokens.set(connectionId, { token: t.accessToken, until: Date.now() + (t.expiresIn - 120) * 1000 });

    const [sites, props] = await Promise.all([
      o.google.searchConsoleSites(t.accessToken).catch(() => []),
      o.google.analyticsProperties(t.accessToken).catch(() => []),
    ]);
    const rows = [...sites.map(x => ({ ...x, kind: 'search_console_site' })), ...props.map(x => ({ ...x, kind: 'ga4_property' }))];
    if (rows.length) {
      q(`BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
        INSERT INTO connection_properties (connection_id, agency_id, client_id, kind, external_id, label)
          SELECT :'conn'::uuid, :'a'::uuid, :'c'::uuid, r->>'kind', r->>'id', r->>'label' FROM jsonb_array_elements(:'rows'::jsonb) r
          ON CONFLICT DO NOTHING;
        -- When exactly one site/property of a kind came back and the client has none selected yet, select it.
        UPDATE connection_properties p SET selected = true WHERE p.connection_id = :'conn'::uuid
          AND (SELECT count(*) FROM connection_properties x WHERE x.connection_id = p.connection_id AND x.kind = p.kind) = 1
          AND NOT EXISTS (SELECT 1 FROM connection_properties y WHERE y.client_id = p.client_id AND y.kind = p.kind AND y.selected);
        SELECT 'null'::json; COMMIT;`, { actor: signedIn.email, conn: connectionId, a: s.agencyId, c: s.clientId, rows: JSON.stringify(rows) });
    }
    return s.clientId;
  }

  /** An access token for a connection, refreshing it when needed; marks the connection for reconnect if Google refuses. */
  async function accessToken(connectionId: string): Promise<string> {
    const hit = tokens.get(connectionId);
    if (hit && hit.until > Date.now()) return hit.token;
    const c = q<{ ref: string | null; agencyId: string; status: string } | null>(
      `SELECT json_build_object('ref', token_ref, 'agencyId', agency_id, 'status', status) FROM connections WHERE id = :'c'::uuid;`, { c: connectionId });
    if (!c || !c.ref || c.status !== 'connected') throw new GoogleError(409, 'Reconnect this Google account', true);
    const app = googleAppFor(c.agencyId);
    try {
      const r = await o.google.refresh(app, JSON.parse(o.secrets.get(c.ref)).refreshToken);
      tokens.set(connectionId, { token: r.accessToken, until: Date.now() + (r.expiresIn - 120) * 1000 });
      return r.accessToken;
    } catch (e) {
      if (e instanceof GoogleError && e.reconnect) {
        q(`BEGIN; SELECT set_config('app.actor', 'system:token-refresh', true) \\g /dev/null
          UPDATE connections SET status = 'needs_reconnect' WHERE id = :'c'::uuid AND status = 'connected'; SELECT 'null'::json; COMMIT;`, { c: connectionId });
      }
      throw e;
    }
  }

  /** Connections and properties a member can see for a client. */
  function list(m: Member, clientId: string) {
    return asMember(o.db, m.workspace.membershipId, m.email, `
      SELECT coalesce(json_agg(json_build_object('id', c.id, 'provider', c.provider, 'account', c.account_email, 'status', c.status,
        'connectedBy', c.connected_by, 'connectedAt', c.connected_at, 'agencyApp', c.via_agency_app,
        'properties', (SELECT coalesce(json_agg(json_build_object('id', p.id, 'kind', p.kind, 'label', p.label, 'selected', p.selected) ORDER BY p.kind, p.label), '[]')
                       FROM connection_properties p WHERE p.connection_id = c.id)) ORDER BY c.connected_at DESC), '[]')
      FROM connections c WHERE c.client_id = :'c'::uuid AND c.status <> 'disconnected';`, { c: clientId });
  }

  function selectProperty(m: Member, propertyId: string): void {
    try { asMember(o.db, m.workspace.membershipId, m.email, `SELECT select_property(:'p'::uuid); SELECT 'null'::json;`, { p: propertyId }); }
    catch (e) { throw new AuthError(403, dbMessage(e, 'You can’t change this')); }
    cache.clear();
  }

  async function disconnect(m: Member, connectionId: string): Promise<void> {
    let ref: string | null;
    try { ref = asMember<string | null>(o.db, m.workspace.membershipId, m.email, `SELECT to_json(disconnect_connection(:'c'::uuid));`, { c: connectionId }); }
    catch (e) { throw new AuthError(/not found/i.test(dbMessage(e, '')) ? 404 : 403, dbMessage(e, 'You can’t disconnect this account')); }
    tokens.delete(connectionId); cache.clear();
    if (!ref) return;
    try { await o.google.revoke(JSON.parse(o.secrets.get(ref)).refreshToken); } catch { /* the token is deleted either way */ }
    o.secrets.delete(ref);
  }

  /** The SEO tab: Search Console clicks by week, totals, top queries and pages, plus Analytics totals. */
  async function seo(m: Member, clientId: string) {
    const ok = asMember<boolean>(o.db, m.workspace.membershipId, m.email, `SELECT to_json(can_reach_client(:'c'::uuid) AND current_can('seo', 'view'));`, { c: clientId });
    if (!ok) throw new AuthError(403, 'Your role doesn’t include SEO for this client');
    const sel = q<{ kind: string; ext: string; label: string; conn: string; status: string }[]>(`
      SELECT coalesce(json_agg(json_build_object('kind', p.kind, 'ext', p.external_id, 'label', p.label, 'conn', c.id, 'status', c.status)), '[]')
      FROM connection_properties p JOIN connections c ON c.id = p.connection_id
      WHERE p.client_id = :'c'::uuid AND p.selected AND c.status <> 'disconnected';`, { c: clientId });
    const site = sel.find(x => x.kind === 'search_console_site'), ga = sel.find(x => x.kind === 'ga4_property');
    if (!site && !ga) return { connected: false };
    const key = `${clientId}|${site?.ext}|${ga?.ext}`;
    const hit = cache.get(key);
    if (hit && hit.until > Date.now()) return hit.data;

    const end = addDays(now(), -3);            // Search Console data settles after about 3 days
    const out: Record<string, unknown> = { connected: true, site: site?.label ?? null, property: ga?.label ?? null, through: day(end) };
    try {
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
        const sum = (from: number, to: number, k: 'clicks' | 'impressions') =>
          daily.filter(r => { const d = Date.parse(r.keys[0]); return d >= Date.parse(day(addDays(end, from))) && d <= Date.parse(day(addDays(end, to))); })
               .reduce((a, r) => a + r[k], 0);
        const posNow = daily.filter(r => Date.parse(r.keys[0]) >= Date.parse(day(addDays(end, -27))));
        out.weeks = weeks;
        out.totals = { clicks: sum(-27, 0, 'clicks'), clicksPrev: sum(-55, -28, 'clicks'), impressions: sum(-27, 0, 'impressions'),
          position: posNow.length ? posNow.reduce((a, r) => a + r.position * r.impressions, 0) / Math.max(1, posNow.reduce((a, r) => a + r.impressions, 0)) : null };
        out.queries = queries.map(r => ({ query: r.keys[0], clicks: r.clicks, impressions: r.impressions, position: r.position }));
        out.pages = pages.map(r => ({ page: r.keys[0], clicks: r.clicks, impressions: r.impressions, position: r.position }));
      }
      if (ga) {
        if (ga.status !== 'connected') throw new GoogleError(409, 'Reconnect this Google account', true);
        const token = await accessToken(ga.conn);
        out.analytics = await o.google.analyticsTotals(token, ga.ext, day(addDays(end, -27)), day(end));
      }
    } catch (e) {
      if (e instanceof GoogleError) return { connected: true, error: e.message, reconnect: e.reconnect };
      throw e;
    }
    cache.set(key, { data: out, until: Date.now() + 30 * 60_000 });
    return out;
  }

  /** Agency owners can bring their own Google OAuth app; the secret goes to the secret store. */
  function saveAgencyApp(m: Member, provider: 'google' | 'meta', appClientId: string, appSecret: string): void {
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

  return { startGoogle, finishGoogle, list, selectProperty, disconnect, seo, saveAgencyApp, accessToken };
}
export type Connections = ReturnType<typeof createConnections>;
