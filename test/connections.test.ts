// Connected accounts against a simulated Google: connect, choose properties, read SEO data,
// refresh failures, disconnect (token deleted and revoked) and the security rules around it.
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
import { createGoogle, type FetchFn } from '../src/google.ts';
import { query, asMember } from '../src/db.ts';
import { freshDb, psql } from './helpers.ts';

const { cfg, drop } = freshDb('conn');
let server: Server, base = '';
const secretsFile = join(mkdtempSync(join(tmpdir(), 'ordix-')), 's.json');
const revoked: string[] = [];
let refreshFails = false;

// ---- a small simulated Google ----
const idToken = (email: string) => `x.${Buffer.from(JSON.stringify({ email })).toString('base64url')}.y`;
const fakeFetch: FetchFn = async (url, init) => {
  const json = (status: number, body: unknown) => ({ ok: status < 400, status, json: async () => body });
  const form = new URLSearchParams(init?.body ?? '');
  if (url === 'https://oauth2.googleapis.com/token') {
    if (form.get('grant_type') === 'authorization_code') {
      if (form.get('code') !== 'good-code') return json(400, { error: 'invalid_grant', error_description: 'Bad code' });
      return json(200, { access_token: 'access-1', refresh_token: `refresh-${Math.random()}`, expires_in: 3600, scope: 'openid email https://www.googleapis.com/auth/webmasters.readonly', id_token: idToken('owner@desertsmiles.example') });
    }
    if (refreshFails) return json(400, { error: 'invalid_grant' });
    return json(200, { access_token: 'access-2', expires_in: 3600 });
  }
  if (url.startsWith('https://oauth2.googleapis.com/revoke')) { revoked.push(new URL(url).searchParams.get('token')!); return json(200, {}); }
  if (url === 'https://www.googleapis.com/webmasters/v3/sites')
    return json(200, { siteEntry: [{ siteUrl: 'sc-domain:desertsmiles.example', permissionLevel: 'siteOwner' }, { siteUrl: 'https://unverified.example/', permissionLevel: 'siteUnverifiedUser' }] });
  if (url.startsWith('https://analyticsadmin.googleapis.com/'))
    return json(200, { accountSummaries: [{ displayName: 'Desert Smiles', propertySummaries: [{ property: 'properties/123', displayName: 'Website' }] }] });
  if (url.includes('/searchAnalytics/query')) {
    const b = JSON.parse(init?.body ?? '{}');
    if (b.dimensions[0] === 'date') {
      const rows = []; for (let d = Date.parse(b.startDate); d <= Date.parse(b.endDate); d += 86400000)
        rows.push({ keys: [new Date(d).toISOString().slice(0, 10)], clicks: 10, impressions: 200, ctr: 0.05, position: 12 });
      return json(200, { rows });
    }
    if (b.dimensions[0] === 'query') return json(200, { rows: [{ keys: ['family dentist mesa'], clicks: 120, impressions: 900, ctr: 0.13, position: 2.4 }] });
    return json(200, { rows: [{ keys: ['https://desertsmiles.example/'], clicks: 200, impressions: 3000, ctr: 0.07, position: 6 }] });
  }
  if (url.includes(':runReport')) return json(200, { rows: [{ metricValues: [{ value: '1500' }, { value: '42' }, { value: '1100' }] }] });
  return json(404, {});
};

function client() {
  let cookie = '';
  return async (method: string, path: string, body?: unknown) => {
    const r = await fetch(base + path, { method, redirect: 'manual', headers: { 'content-type': 'application/json', 'x-requested-with': 'ordix', cookie }, body: body ? JSON.stringify(body) : undefined });
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

let owner: ReturnType<typeof client>, other: ReturnType<typeof client>, analyst: ReturnType<typeof client>, lena: ReturnType<typeof client>;
let dental = '';
before(async () => {
  createAgency(cfg, { name: 'Brightline Digital', slug: 'brightline', ownerEmail: 'dana@brightline.example', ownerName: 'Dana Ortiz' }, 't');
  createAgency(cfg, { name: 'Copperline Marketing', slug: 'copperline', ownerEmail: 'kim@copperline.example', ownerName: 'Kim Lee' }, 't');
  server = createAppServer({ db: cfg, secrets: new LocalEncryptedStore(secretsFile, 'a'.repeat(64)), google: createGoogle({ fetchFn: fakeFetch }),
    googleApp: { clientId: 'ordix-client-id', clientSecret: 'ordix-secret' }, publicUrl: 'https://app.ordixit.com' });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  owner = await onboard('dana@brightline.example');
  other = await onboard('kim@copperline.example');
  dental = (await owner('POST', '/api/clients', { name: 'Desert Smiles Dental', domain: 'desertsmiles.example', cms: 'wordpress' })).data.id;
  await owner('POST', '/api/team', { fullName: 'Ana Lyst', email: 'ana@brightline.example', template: 'analyst' });
  await owner('POST', '/api/team', { fullName: 'Lena Ruiz', email: 'lena@desertsmiles.example', template: 'client_admin', clientId: dental });
  analyst = await onboard('ana@brightline.example');
  lena = await onboard('lena@desertsmiles.example');
});
after(() => { server.close(); drop(); });

let connId = '';
test('connecting sends the browser to Google with read-only scopes and Ordix’s redirect', async () => {
  const r = await owner('POST', `/api/clients/${dental}/connections/google`, {});
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const u = new URL(r.data.url);
  assert.equal(u.origin, 'https://accounts.google.com');
  assert.equal(u.searchParams.get('redirect_uri'), 'https://app.ordixit.com/oauth/google/callback');
  assert.equal(u.searchParams.get('access_type'), 'offline');
  assert.match(u.searchParams.get('scope')!, /webmasters\.readonly.*analytics\.readonly/);
  assert.ok(!/(webmasters|analytics)( |$)/.test(u.searchParams.get('scope')!), 'never write scopes');

  assert.equal((await client()('GET', '/oauth/google/callback?state=x&code=y')).status, 200, 'the return page loads without a session');
  const done = await owner('POST', '/oauth/google/finish', { query: `?state=${stateFrom(r.data.url)}&code=good-code` });
  assert.equal(done.status, 200, JSON.stringify(done.data));
  assert.equal(done.data.clientId, dental);

  const list = (await owner('GET', `/api/clients/${dental}/connections`)).data;
  assert.equal(list.length, 1);
  connId = list[0].id;
  assert.equal(list[0].account, 'owner@desertsmiles.example');
  const labels = list[0].properties.map((p: { label: string; selected: boolean }) => [p.label, p.selected]);
  assert.deepEqual(labels, [['Website (Desert Smiles)', true], ['desertsmiles.example', true]], 'unverified sites are skipped; single choices are selected');
});

test('a sign-in link works once, and only for the person who started it', async () => {
  const r = await owner('POST', `/api/clients/${dental}/connections/google`, {});
  const state = stateFrom(r.data.url);
  const stolen = await other('POST', '/oauth/google/finish', { query: `?state=${state}&code=good-code` });
  assert.equal(stolen.status, 403);
  const reused = await owner('POST', '/oauth/google/finish', { query: `?state=${state}&code=good-code` });
  assert.equal(reused.status, 400, 'the attempt above used up the link');
  const r2 = await owner('POST', `/api/clients/${dental}/connections/google`, {});
  psql(cfg, `UPDATE oauth_states SET expires_at = now() - interval '1 minute' WHERE used_at IS NULL;`);
  assert.equal((await owner('POST', '/oauth/google/finish', { query: `?state=${stateFrom(r2.data.url)}&code=good-code` })).status, 400, 'expired');
});

test('the SEO tab shows Search Console and Analytics numbers', async () => {
  const d = (await owner('GET', `/api/clients/${dental}/seo`)).data;
  assert.equal(d.connected, true);
  assert.equal(d.weeks.length, 12);
  assert.ok(d.weeks.every((w: { clicks: number }) => w.clicks === 70), 'seven days of 10 clicks per week');
  assert.equal(d.totals.clicks, 280);
  assert.equal(d.totals.position, 12);
  assert.equal(d.queries[0].query, 'family dentist mesa');
  assert.deepEqual(d.analytics, { sessions: 1500, keyEvents: 42, users: 1100 });
});

test('people without connect access can’t connect; client admins can for their own client', async () => {
  assert.equal((await analyst('POST', `/api/clients/${dental}/connections/google`, {})).status, 403);
  assert.equal((await lena('POST', `/api/clients/${dental}/connections/google`, {})).status, 200);
  assert.equal((await lena('GET', `/api/clients/${dental}/connections`)).data.length, 1);
});

test('another agency can’t see, use or disconnect the connection', async () => {
  assert.equal((await other('POST', `/api/clients/${dental}/connections/google`, {})).status, 403);
  assert.equal((await other('GET', `/api/clients/${dental}/seo`)).status, 403);
  assert.equal((await other('GET', `/api/clients/${dental}/connections`)).data.length, 0);
  assert.equal((await other('POST', `/api/connections/${connId}/disconnect`, {})).status, 404);
});

test('members can never read token references or agency app secrets', () => {
  const owner = query<string>(cfg, `SELECT to_json(id) FROM memberships WHERE is_owner LIMIT 1;`);
  assert.throws(() => asMember(cfg, owner, 'x', `SELECT token_ref FROM connections;`), /permission denied/);
  assert.throws(() => asMember(cfg, owner, 'x', `SELECT secret_ref FROM oauth_apps;`), /permission denied/);
  assert.throws(() => asMember(cfg, owner, 'x', `SELECT * FROM oauth_states;`), /permission denied/);
  const audit = query<string>(cfg, `SELECT to_json(string_agg(coalesce(after::text, ''), '')) FROM audit_log WHERE entity = 'connections';`);
  assert.ok(!audit.includes('token_ref'), 'token references never reach the audit log');
});

test('an expired Google sign-in marks the connection for reconnect', async () => {
  refreshFails = true;
  // A new server instance has no cached access token, so it must refresh.
  const fresh = createAppServer({ db: cfg, secrets: new LocalEncryptedStore(secretsFile, 'a'.repeat(64)), google: createGoogle({ fetchFn: fakeFetch }),
    googleApp: { clientId: 'ordix-client-id', clientSecret: 'ordix-secret' }, publicUrl: 'https://app.ordixit.com' });
  await new Promise<void>(r => fresh.listen(0, '127.0.0.1', () => r()));
  const old = base; base = `http://127.0.0.1:${(fresh.address() as AddressInfo).port}`;
  const d = (await owner('GET', `/api/clients/${dental}/seo`)).data;
  base = old; fresh.close(); refreshFails = false;
  assert.equal(d.reconnect, true);
  const st = query<string[]>(cfg, `SELECT json_agg(status) FROM connections WHERE client_id = '${dental}';`);
  assert.ok(st.includes('needs_reconnect'));
});

test('disconnecting deletes the token, revokes it with Google and removes synced data', async () => {
  const before = Object.keys(JSON.parse(readFileSync(secretsFile, 'utf8'))).length;
  const r = await owner('POST', `/api/connections/${connId}/disconnect`, {});
  assert.equal(r.status, 200);
  assert.equal(Object.keys(JSON.parse(readFileSync(secretsFile, 'utf8'))).length, before - 1, 'token removed from the secret store');
  assert.equal(revoked.length, 1);
  assert.equal(query<number>(cfg, `SELECT count(*) FROM connection_properties WHERE connection_id = '${connId}';`), 0);
  assert.equal(query<string>(cfg, `SELECT to_json(status) FROM connections WHERE id = '${connId}';`), 'disconnected');
  assert.throws(() => psql(cfg, `UPDATE connections SET status = 'connected' WHERE id = '${connId}';`), /stays disconnected/);
});

test('only the owner can set the agency’s own Google app, and the secret stays in the secret store', async () => {
  assert.equal((await analyst('POST', '/api/agency/oauth-app', { provider: 'google', clientId: 'x', clientSecret: 'y'.repeat(20) })).status, 403);
  assert.equal((await owner('POST', '/api/agency/oauth-app', { provider: 'google', clientId: 'agency-client-id', clientSecret: 'agency-secret-123' })).status, 200);
  const apps = (await owner('GET', '/api/agency/oauth-app')).data;
  assert.deepEqual(apps.map((a: { clientId: string }) => a.clientId), ['agency-client-id']);
  assert.ok(!JSON.stringify(apps).includes('agency-secret'));
  const r = await owner('POST', `/api/clients/${dental}/connections/google`, {});
  assert.equal(new URL(r.data.url).searchParams.get('client_id'), 'agency-client-id', 'the agency’s own app is used');
});
