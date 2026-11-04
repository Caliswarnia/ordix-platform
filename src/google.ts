// Google: OAuth sign-in for a client's own account, then read-only Search Console and Analytics data.
// Every network call goes through `fetchFn`, so tests run against a simulated Google.
//
// Scopes are read-only: Ordix never changes anything in a client's Google account.
// Testing-mode note: until Google verifies the Ordix app, refresh tokens expire after 7 days;
// a failed refresh marks the connection "needs reconnect".

export const GOOGLE_SCOPES = [
  'openid', 'email',
  'https://www.googleapis.com/auth/webmasters.readonly',
  'https://www.googleapis.com/auth/analytics.readonly',
];

export type FetchFn = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) =>
  Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

export interface GoogleApp { clientId: string; clientSecret: string; redirectUri: string }
export class GoogleError extends Error {
  status: number; reconnect: boolean;
  constructor(status: number, msg: string, reconnect = false) { super(msg); this.status = status; this.reconnect = reconnect; }
}

export function authUrl(app: GoogleApp, state: string, loginHint?: string): string {
  const q = new URLSearchParams({
    client_id: app.clientId, redirect_uri: app.redirectUri, response_type: 'code', scope: GOOGLE_SCOPES.join(' '),
    access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true', state,
  });
  if (loginHint) q.set('login_hint', loginHint);
  return `https://accounts.google.com/o/oauth2/v2/auth?${q}`;
}

function emailFromIdToken(idToken: string | undefined): string | null {
  if (!idToken) return null;
  try { return JSON.parse(Buffer.from(idToken.split('.')[1], 'base64url').toString('utf8')).email ?? null; } catch { return null; }
}

export function createGoogle(o: { fetchFn?: FetchFn } = {}) {
  const f: FetchFn = o.fetchFn ?? ((url, init) => fetch(url, init) as unknown as ReturnType<FetchFn>);
  const form = (data: Record<string, string>) => ({
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(data).toString(),
  });

  async function call(url: string, token: string, init: { method?: string; body?: unknown } = {}) {
    const r = await f(url, { method: init.method ?? 'GET',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: init.body === undefined ? undefined : JSON.stringify(init.body) });
    if (r.status === 401) throw new GoogleError(401, 'Google sign-in expired', true);
    if (r.status === 403) throw new GoogleError(403, 'This Google account doesn’t have access to that data');
    if (!r.ok) throw new GoogleError(502, `Google returned an error (${r.status})`);
    return r.json();
  }

  return {
    /** Exchanges the code from the redirect for tokens. */
    async exchangeCode(app: GoogleApp, code: string) {
      const r = await f('https://oauth2.googleapis.com/token', form({ code, client_id: app.clientId, client_secret: app.clientSecret, redirect_uri: app.redirectUri, grant_type: 'authorization_code' }));
      const d = await r.json();
      if (!r.ok || !d.refresh_token) throw new GoogleError(400, d.error_description ?? 'Google didn’t complete the sign-in. Try again.');
      return { refreshToken: d.refresh_token as string, accessToken: d.access_token as string, expiresIn: Number(d.expires_in ?? 3600),
               scopes: String(d.scope ?? '').split(' ').filter(Boolean), email: emailFromIdToken(d.id_token) };
    },
    /** A fresh access token; an invalid_grant means the person must reconnect. */
    async refresh(app: { clientId: string; clientSecret: string }, refreshToken: string) {
      const r = await f('https://oauth2.googleapis.com/token', form({ refresh_token: refreshToken, client_id: app.clientId, client_secret: app.clientSecret, grant_type: 'refresh_token' }));
      const d = await r.json();
      if (!r.ok) throw new GoogleError(401, 'Google sign-in expired. Reconnect the account.', d.error === 'invalid_grant' || r.status === 400 || r.status === 401);
      return { accessToken: d.access_token as string, expiresIn: Number(d.expires_in ?? 3600) };
    },
    async revoke(token: string) {
      try { await f(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`, { method: 'POST' }); } catch { /* best effort */ }
    },
    async searchConsoleSites(token: string): Promise<{ id: string; label: string }[]> {
      const d = await call('https://www.googleapis.com/webmasters/v3/sites', token);
      return (d.siteEntry ?? [])
        .filter((s: { permissionLevel: string }) => s.permissionLevel !== 'siteUnverifiedUser')
        .map((s: { siteUrl: string }) => ({ id: s.siteUrl, label: s.siteUrl.replace(/^sc-domain:/, '').replace(/^https?:\/\//, '').replace(/\/$/, '') }));
    },
    async analyticsProperties(token: string): Promise<{ id: string; label: string }[]> {
      const d = await call('https://analyticsadmin.googleapis.com/v1beta/accountSummaries?pageSize=200', token);
      const out: { id: string; label: string }[] = [];
      for (const a of d.accountSummaries ?? []) for (const p of a.propertySummaries ?? []) out.push({ id: p.property, label: `${p.displayName} (${a.displayName})` });
      return out;
    },
    /** Search Console rows for a date range, grouped by the given dimensions. */
    async searchAnalytics(token: string, siteUrl: string, body: { startDate: string; endDate: string; dimensions: string[]; rowLimit?: number }) {
      const d = await call(`https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/searchAnalytics/query`, token, { method: 'POST', body: { ...body, dataState: 'final' } });
      return (d.rows ?? []) as { keys: string[]; clicks: number; impressions: number; ctr: number; position: number }[];
    },
    /** GA4 totals for a date range. */
    async analyticsTotals(token: string, property: string, startDate: string, endDate: string) {
      const d = await call(`https://analyticsdata.googleapis.com/v1beta/${property}:runReport`, token, { method: 'POST',
        body: { dateRanges: [{ startDate, endDate }], metrics: [{ name: 'sessions' }, { name: 'keyEvents' }, { name: 'totalUsers' }] } });
      const v = d.rows?.[0]?.metricValues ?? [];
      return { sessions: Number(v[0]?.value ?? 0), keyEvents: Number(v[1]?.value ?? 0), users: Number(v[2]?.value ?? 0) };
    },
  };
}
export type Google = ReturnType<typeof createGoogle>;
