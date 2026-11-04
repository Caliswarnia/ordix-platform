// Meta (Facebook and Instagram): OAuth sign-in for a client's own account, then read-only ad reporting.
// Every network call goes through `fetchFn`, so tests run against a simulated Meta.
//
// Permissions are read-only: ads_read (never ads_management) and page listing; Ordix never changes ads.
// Meta has no refresh token: the short-lived token is exchanged for a long-lived one (about 60 days),
// after which the person reconnects. Version: Marketing API v25.0 (released 2026-02-18); set META_API_VERSION to move.
import type { FetchFn } from './google.ts';

export const META_SCOPES = ['email', 'ads_read', 'pages_show_list', 'pages_read_engagement'];
export const META_VERSION = process.env.META_API_VERSION ?? 'v25.0';

export interface MetaApp { clientId: string; clientSecret: string; redirectUri: string }
export class MetaError extends Error {
  status: number; reconnect: boolean;
  constructor(status: number, msg: string, reconnect = false) { super(msg); this.status = status; this.reconnect = reconnect; }
}

export function metaAuthUrl(app: MetaApp, state: string, version = META_VERSION): string {
  const q = new URLSearchParams({ client_id: app.clientId, redirect_uri: app.redirectUri, state, response_type: 'code', scope: META_SCOPES.join(',') });
  return `https://www.facebook.com/${version}/dialog/oauth?${q}`;
}

/** Meta returns ad actions as a list; picks the total for the given action types. */
function actionTotal(list: { action_type: string; value: string }[] | undefined, types: string[]): number {
  return (list ?? []).filter(a => types.includes(a.action_type)).reduce((s, a) => s + Number(a.value || 0), 0);
}
const LEAD_TYPES = ['lead', 'onsite_conversion.lead_grouped', 'offsite_conversion.fb_pixel_lead'];
const PURCHASE_TYPES = ['purchase', 'omni_purchase', 'offsite_conversion.fb_pixel_purchase'];

export function createMeta(o: { fetchFn?: FetchFn; version?: string } = {}) {
  const f: FetchFn = o.fetchFn ?? ((url, init) => fetch(url, init) as unknown as ReturnType<FetchFn>);
  const v = o.version ?? META_VERSION;
  const graph = (path: string, params: Record<string, string>) => `https://graph.facebook.com/${v}/${path}?${new URLSearchParams(params)}`;

  async function get(path: string, token: string, params: Record<string, string> = {}) {
    const r = await f(graph(path, { ...params, access_token: token }));
    const d = await r.json().catch(() => ({}));
    if (!r.ok) {
      const code = d?.error?.code;
      if (code === 190 || r.status === 401) throw new MetaError(401, 'Meta sign-in expired. Reconnect the account.', true);
      if (code === 10 || code === 200 || r.status === 403) throw new MetaError(403, 'This Meta account doesn’t have access to that data');
      if (code === 4 || code === 17 || code === 80004) throw new MetaError(429, 'Meta is limiting requests right now. Try again in a few minutes.');
      throw new MetaError(502, `Meta returned an error (${r.status})`);
    }
    return d;
  }
  async function all(path: string, token: string, params: Record<string, string>) {
    const out: any[] = [];
    let d = await get(path, token, { ...params, limit: '200' });
    out.push(...(d.data ?? []));
    for (let i = 0; i < 4 && d.paging?.next; i++) {          // a few pages at most
      const r = await f(d.paging.next); d = await r.json(); out.push(...(d.data ?? []));
    }
    return out;
  }

  return {
    version: v,
    /** Code from the redirect, then a long-lived token (about 60 days). */
    async exchangeCode(app: MetaApp, code: string) {
      const r1 = await f(graph('oauth/access_token', { client_id: app.clientId, client_secret: app.clientSecret, redirect_uri: app.redirectUri, code }));
      const d1 = await r1.json();
      if (!r1.ok || !d1.access_token) throw new MetaError(400, d1?.error?.message ?? 'Meta didn’t complete the sign-in. Try again.');
      const r2 = await f(graph('oauth/access_token', { grant_type: 'fb_exchange_token', client_id: app.clientId, client_secret: app.clientSecret, fb_exchange_token: d1.access_token }));
      const d2 = await r2.json();
      if (!r2.ok || !d2.access_token) throw new MetaError(400, 'Meta didn’t complete the sign-in. Try again.');
      const me = await get('me', d2.access_token, { fields: 'id,name,email' }).catch(() => ({}));
      const perms = await get('me/permissions', d2.access_token).catch(() => ({ data: [] }));
      return { accessToken: d2.access_token as string, expiresIn: Number(d2.expires_in ?? 60 * 86400),
               email: (me.email ?? me.name ?? null) as string | null,
               scopes: (perms.data ?? []).filter((p: { status: string }) => p.status === 'granted').map((p: { permission: string }) => p.permission) as string[] };
    },
    async revoke(token: string) {
      try { await f(graph('me/permissions', { access_token: token }), { method: 'DELETE' }); } catch { /* best effort */ }
    },
    async adAccounts(token: string): Promise<{ id: string; label: string }[]> {
      const rows = await all('me/adaccounts', token, { fields: 'id,name,currency,account_status' });
      return rows.map((a: { id: string; name: string; currency: string; account_status: number }) =>
        ({ id: a.id, label: `${a.name} (${a.currency}${a.account_status === 1 ? '' : ', not active'})` }));
    },
    async pages(token: string): Promise<{ id: string; label: string }[]> {
      const rows = await all('me/accounts', token, { fields: 'id,name' });   // page tokens are not requested or kept
      return rows.map((p: { id: string; name: string }) => ({ id: p.id, label: p.name }));
    },
    /** Spend and results for an ad account: weekly spend, totals and top campaigns. */
    async adReport(token: string, adAccountId: string, since: string, until: string, prevSince: string, prevUntil: string) {
      const fields = 'spend,impressions,clicks,actions,action_values,purchase_roas,account_currency';
      const [weekly, total, prev, campaigns] = await Promise.all([
        get(`${adAccountId}/insights`, token, { fields: 'spend,date_start,date_stop', time_range: JSON.stringify({ since, until }), time_increment: '7' }),
        get(`${adAccountId}/insights`, token, { fields, time_range: JSON.stringify({ since: addDays(until, -27), until }) }),
        get(`${adAccountId}/insights`, token, { fields: 'spend', time_range: JSON.stringify({ since: prevSince, until: prevUntil }) }),
        get(`${adAccountId}/insights`, token, { level: 'campaign', fields: 'campaign_name,spend,clicks,actions,purchase_roas', time_range: JSON.stringify({ since: addDays(until, -27), until }), sort: 'spend_descending', limit: '10' }),
      ]);
      const t = total.data?.[0] ?? {};
      const spend = Number(t.spend ?? 0);
      const purchaseValue = actionTotal(t.action_values, PURCHASE_TYPES);
      return {
        currency: t.account_currency ?? null,
        weeks: (weekly.data ?? []).map((w: { date_start: string; date_stop: string; spend: string }) => ({ weekEnding: w.date_stop, spend: Number(w.spend ?? 0) })),
        totals: { spend, spendPrev: Number(prev.data?.[0]?.spend ?? 0), impressions: Number(t.impressions ?? 0), clicks: Number(t.clicks ?? 0),
          leads: actionTotal(t.actions, LEAD_TYPES), purchases: actionTotal(t.actions, PURCHASE_TYPES), purchaseValue,
          roas: spend > 0 && purchaseValue > 0 ? purchaseValue / spend : null },
        campaigns: (campaigns.data ?? []).map((c: { campaign_name: string; spend: string; clicks: string; actions?: { action_type: string; value: string }[] }) =>
          ({ name: c.campaign_name, spend: Number(c.spend ?? 0), clicks: Number(c.clicks ?? 0), leads: actionTotal(c.actions, LEAD_TYPES) })),
      };
    },
  };
}
function addDays(day: string, n: number): string { return new Date(Date.parse(day) + n * 86400000).toISOString().slice(0, 10); }
export type Meta = ReturnType<typeof createMeta>;
