// Meta against a simulated Graph API: connect, long-lived token, ad accounts and pages, the Paid media
// report, the 60-day expiry, disconnect (token deleted and revoked) and the access rules.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAppServer } from '../src/server.ts';
import { LocalEncryptedStore } from '../src/secrets.ts';
import { createAgency } from '../src/access.ts';
import { issueTemporaryPassword, totp, fromBase32 } from '../src/auth.ts';
import { createMeta } from '../src/meta.ts';
import { createGoogle, type FetchFn } from '../src/google.ts';
import { query } from '../src/db.ts';
import { freshDb, psql } from './helpers.ts';

const { cfg, drop } = freshDb('meta');
let server: Server, base = '';
const secretsFile = join(mkdtempSync(join(tmpdir(), 'ordix-')), 's.json');
const calls: string[] = [];
let revokedWith = '';

const fakeMeta: FetchFn = async (url, init) => {
  calls.push(url);
  const json = (status: number, body: unknown) => ({ ok: status < 400, status, json: async () => body });
  const u = new URL(url), p = u.pathname.replace(/^\/v\d+\.\d+\//, ''), q = u.searchParams;
  if (p === 'oauth/access_token' && q.get('code')) return q.get('code') === 'good' ? json(200, { access_token: 'short-token' }) : json(400, { error: { message: 'Invalid code' } });
  if (p === 'oauth/access_token' && q.get('grant_type') === 'fb_exchange_token') return json(200, { access_token: 'long-token', expires_in: 60 * 86400 });
  if (q.get('access_token') === 'expired') return json(400, { error: { code: 190, message: 'Session has expired' } });
  if (p === 'me' ) return json(200, { id: '1', name: 'Lena Ruiz', email: 'lena@desertsmiles.example' });
  if (p === 'me/permissions' && init?.method === 'DELETE') { revokedWith = q.get('access_token')!; return json(200, { success: true }); }
  if (p === 'me/permissions') return json(200, { data: [{ permission: 'ads_read', status: 'granted' }, { permission: 'pages_show_list', status: 'granted' }, { permission: 'email', status: 'declined' }] });
  if (p === 'me/adaccounts') return json(200, { data: [{ id: 'act_111', name: 'Desert Smiles', currency: 'USD', account_status: 1 }] });
  if (p === 'me/accounts') return json(200, { data: [{ id: '222', name: 'Desert Smiles Dental' }, { id: '333', name: 'Desert Smiles Kids' }] });
  if (p === 'act_111/insights') {
    if (q.get('time_increment') === '7') return json(200, { data: Array.from({ length: 12 }, (_, i) => ({ date_start: `w${i}`, date_stop: `2026-10-${String(i + 1).padStart(2, '0')}`, spend: String(100 + i * 10) })) });
    if (q.get('level') === 'campaign') return json(200, { data: [{ campaign_name: 'Saturday hours', spend: '420.50', clicks: '310', actions: [{ action_type: 'lead', value: '18' }] }] });
    if (q.get('fields') === 'spend') return json(200, { data: [{ spend: '1000' }] });
    return json(200, { data: [{ spend: '1200', impressions: '48000', clicks: '960', account_currency: 'USD',
      actions: [{ action_type: 'lead', value: '30' }, { action_type: 'onsite_conversion.lead_grouped', value: '6' }, { action_type: 'link_click', value: '900' }],
      action_values: [{ action_type: 'purchase', value: '4800' }] }] });
  }
  return json(404, { error: { message: 'unknown' } });
};

function client() {
  let cookie = '';
  return async (method: string, path: string, body?: unknown) => {
    const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-requested-with': 'ordix', cookie }, body: body ? JSON.stringify(body) : undefined });
    const set = r.headers.get('set-cookie'); if (set) cookie = set.split(';')[0];
    return { status: r.status, data: (r.headers.get('content-type') ?? '').includes('json') ? await r.json() as any : await r.text() };
  };
}
const personId = (email: string) => query<string>(cfg, `SELECT to_json(id) FROM people WHERE email = '${email}';`);
async function onboard(email: string) {
  const temp = issueTemporaryPassword(cfg, personId(email), { resetMfa: false }, 't').temporaryPassword;
  const call = client();
  const r = await call('POST', '/auth/sign-in', { email, password: temp });
  psql(cfg, `UPDATE person_sign_in SET last_totp_step = NULL WHERE person_id = '${personId(email)}';`);
  await call('POST', '/auth/verify', { challenge: r.data.challenge, code: totp(fromBase32(r.data.secret), Math.floor(Date.now() / 30000)) });
  await call('POST', '/auth/password', { current: temp, next: `${email}-passphrase` });
  return call;
}
const stateFrom = (url: string) => new URL(url).searchParams.get('state')!;

let owner: ReturnType<typeof client>, other: ReturnType<typeof client>, seo: ReturnType<typeof client>;
let dental = '', connId = '';
before(async () => {
  createAgency(cfg, { name: 'Brightline Digital', slug: 'brightline', ownerEmail: 'dana@brightline.example', ownerName: 'Dana Ortiz' }, 't');
  createAgency(cfg, { name: 'Copperline Marketing', slug: 'copperline', ownerEmail: 'kim@copperline.example', ownerName: 'Kim Lee' }, 't');
  server = createAppServer({ db: cfg, secrets: new LocalEncryptedStore(secretsFile, 'c'.repeat(64)), google: createGoogle({ fetchFn: fakeMeta }),
    meta: createMeta({ fetchFn: fakeMeta, version: 'v25.0' }), metaApp: { clientId: 'ordix-meta-app', clientSecret: 'ordix-meta-secret' }, publicUrl: 'https://app.ordixit.com' });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  owner = await onboard('dana@brightline.example');
  other = await onboard('kim@copperline.example');
  dental = (await owner('POST', '/api/clients', { name: 'Desert Smiles Dental' })).data.id;
  await owner('POST', '/api/team', { fullName: 'Sam Patel', email: 'sam@brightline.example', template: 'seo_specialist' });
  seo = await onboard('sam@brightline.example');
});
after(() => { server.close(); drop(); });

test('connecting sends the browser to Meta with read-only permissions', async () => {
  const r = await owner('POST', `/api/clients/${dental}/connections/meta`, {});
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const u = new URL(r.data.url);
  assert.equal(u.origin + u.pathname, 'https://www.facebook.com/v25.0/dialog/oauth');
  assert.equal(u.searchParams.get('redirect_uri'), 'https://app.ordixit.com/oauth/meta/callback');
  assert.match(u.searchParams.get('scope')!, /ads_read/);
  assert.ok(!/ads_management|business_management/.test(u.searchParams.get('scope')!), 'never write access to ads');
  assert.equal((await client()('GET', '/oauth/meta/callback?state=x')).status, 200);

  const done = await owner('POST', '/oauth/meta/finish', { query: `?state=${stateFrom(r.data.url)}&code=good` });
  assert.equal(done.status, 200, JSON.stringify(done.data));
  assert.ok(calls.some(c => c.includes('grant_type=fb_exchange_token')), 'short-lived token exchanged for a long-lived one');
  const list = (await owner('GET', `/api/clients/${dental}/connections`)).data;
  connId = list[0].id;
  assert.equal(list[0].provider, 'meta');
  assert.equal(list[0].account, 'lena@desertsmiles.example');
  const days = (Date.parse(list[0].expiresAt) - Date.now()) / 864e5;
  assert.ok(days > 59 && days <= 60, 'expiry recorded about 60 days out');
  const props = list[0].properties.map((p: { kind: string; label: string; selected: boolean }) => [p.kind, p.label, p.selected]);
  assert.deepEqual(props, [['meta_ad_account', 'Desert Smiles (USD)', true], ['meta_page', 'Desert Smiles Dental', false], ['meta_page', 'Desert Smiles Kids', false]],
    'the single ad account is selected; two pages wait for a choice');
  assert.deepEqual(query<string[]>(cfg, `SELECT to_json(scopes) FROM connections WHERE id = '${connId}';`), ['ads_read', 'pages_show_list'], 'only granted permissions are recorded');
});

test('a Meta link can’t be finished on the Google return address', async () => {
  const r = await owner('POST', `/api/clients/${dental}/connections/meta`, {});
  const wrong = await owner('POST', '/oauth/google/finish', { query: `?state=${stateFrom(r.data.url)}&code=good` });
  assert.equal(wrong.status, 400);
  assert.match(wrong.data.error, /different service/);
});

test('the Paid media tab shows spend, leads, return and campaigns', async () => {
  const d = (await owner('GET', `/api/clients/${dental}/ads`)).data;
  assert.equal(d.connected, true);
  assert.equal(d.currency, 'USD');
  assert.equal(d.weeks.length, 12);
  assert.equal(d.totals.spend, 1200);
  assert.equal(d.totals.spendPrev, 1000);
  assert.equal(d.totals.leads, 36, 'lead and grouped lead actions are added; link clicks are not leads');
  assert.equal(d.totals.roas, 4);
  assert.deepEqual(d.campaigns, [{ name: 'Saturday hours', spend: 420.5, clicks: 310, leads: 18 }]);
});

test('people without paid media access, and other agencies, can’t see ad numbers', async () => {
  assert.equal((await seo('GET', `/api/clients/${dental}/ads`)).status, 403);
  assert.equal((await other('GET', `/api/clients/${dental}/ads`)).status, 403);
  assert.equal((await other('POST', `/api/connections/${connId}/disconnect`, {})).status, 404);
});

test('an expired Meta sign-in shows reconnect and marks the connection', async () => {
  const fresh = createAppServer({ db: cfg, secrets: new LocalEncryptedStore(secretsFile, 'c'.repeat(64)), google: createGoogle({ fetchFn: fakeMeta }),
    meta: createMeta({ fetchFn: fakeMeta }), metaApp: { clientId: 'ordix-meta-app', clientSecret: 'ordix-meta-secret' }, publicUrl: 'https://app.ordixit.com' });
  await new Promise<void>(r => fresh.listen(0, '127.0.0.1', () => r()));
  // Rewrite the stored token as already expired (as if 60 days passed).
  const ref = query<string>(cfg, `SELECT to_json(token_ref) FROM connections WHERE id = '${connId}';`);
  const store = new LocalEncryptedStore(secretsFile, 'c'.repeat(64));
  const all = JSON.parse(readFileSync(secretsFile, 'utf8'));
  const newRef = store.put(JSON.stringify({ accessToken: 'long-token', expiresAt: new Date(Date.now() - 1000).toISOString() }));
  psql(cfg, `UPDATE connections SET token_ref = '${newRef}' WHERE id = '${connId}';`);
  store.delete(ref); void all;
  const old = base; base = `http://127.0.0.1:${(fresh.address() as AddressInfo).port}`;
  const d = (await owner('GET', `/api/clients/${dental}/ads`)).data;
  base = old; fresh.close();
  assert.equal(d.reconnect, true);
  assert.equal(query<string>(cfg, `SELECT to_json(status) FROM connections WHERE id = '${connId}';`), 'needs_reconnect');
});

test('disconnecting deletes the token and revokes Ordix’s access in Meta', async () => {
  const before = Object.keys(JSON.parse(readFileSync(secretsFile, 'utf8'))).length;
  assert.equal((await owner('POST', `/api/connections/${connId}/disconnect`, {})).status, 200);
  assert.equal(revokedWith, 'long-token');
  assert.equal(Object.keys(JSON.parse(readFileSync(secretsFile, 'utf8'))).length, before - 1);
  assert.equal((await owner('GET', `/api/clients/${dental}/ads`)).data.connected, false);
});
