// The web app: screens are served, and the API respects access levels and agency walls.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAppServer } from '../src/server.ts';
import { LocalEncryptedStore } from '../src/secrets.ts';
import { createAgency } from '../src/access.ts';
import { issueTemporaryPassword, totp, fromBase32 } from '../src/auth.ts';
import { query } from '../src/db.ts';
import { freshDb, psql } from './helpers.ts';

const { cfg, drop } = freshDb('api');
let server: Server, base = '';
const secrets: Record<string, string> = {};

function client() {
  let cookie = '';
  return async (method: string, path: string, body?: unknown) => {
    const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-requested-with': 'ordix', cookie }, body: body ? JSON.stringify(body) : undefined });
    const set = r.headers.get('set-cookie'); if (set) cookie = set.split(';')[0];
    const type = r.headers.get('content-type') ?? '';
    return { status: r.status, data: type.includes('json') ? await r.json() as any : await r.text(), headers: r.headers };
  };
}
const personId = (email: string) => query<string>(cfg, `SELECT to_json(id) FROM people WHERE email = '${email}';`);

/** Signs in with a temporary password, sets up the authenticator, sets a real password; returns the caller. */
async function onboard(email: string, temp: string) {
  const call = client();
  const r = await call('POST', '/auth/sign-in', { email, password: temp });
  secrets[email] = r.data.secret;
  psql(cfg, `UPDATE person_sign_in SET last_totp_step = NULL WHERE person_id = '${personId(email)}';`);
  const v = await call('POST', '/auth/verify', { challenge: r.data.challenge, code: totp(fromBase32(r.data.secret), Math.floor(Date.now() / 30000)) });
  assert.equal(v.status, 200, JSON.stringify(v.data));
  assert.equal((await call('POST', '/auth/password', { current: temp, next: `${email}-passphrase` })).status, 200);
  return call;
}

let owner: ReturnType<typeof client>, otherOwner: ReturnType<typeof client>;
before(async () => {
  createAgency(cfg, { name: 'Brightline Digital', slug: 'brightline', ownerEmail: 'dana@brightline.example', ownerName: 'Dana Ortiz' }, 'ordix:test');
  createAgency(cfg, { name: 'Copperline Marketing', slug: 'copperline', ownerEmail: 'kim@copperline.example', ownerName: 'Kim Lee' }, 'ordix:test');
  server = createAppServer({ db: cfg, secrets: new LocalEncryptedStore(join(mkdtempSync(join(tmpdir(), 'ordix-')), 's.json'), 'f'.repeat(64)) });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  owner = await onboard('dana@brightline.example', issueTemporaryPassword(cfg, personId('dana@brightline.example'), { resetMfa: false }, 't').temporaryPassword);
  otherOwner = await onboard('kim@copperline.example', issueTemporaryPassword(cfg, personId('kim@copperline.example'), { resetMfa: false }, 't').temporaryPassword);
});
after(() => { server.close(); drop(); });

test('the app page and its files are served with security headers', async () => {
  const r = await client()('GET', '/');
  assert.equal(r.status, 200);
  assert.match(r.data, /<script src="\/app.js">/);
  assert.match(r.headers.get('content-security-policy') ?? '', /default-src 'self'/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal((await client()('GET', '/app.js')).status, 200);
});

test('the API needs a signed-in member', async () => {
  assert.equal((await client()('GET', '/api/session')).status, 401);
});

test('the session shows the agency’s own branding and full owner access', async () => {
  const s = (await owner('GET', '/api/session')).data;
  assert.equal(s.agency.name, 'Brightline Digital');
  assert.equal(s.access.margins, 'approve');
  assert.ok(s.templates.some((t: { key: string }) => t.key === 'client_admin'));
});

let clientId = '', seoId = '';
test('owners add clients, and domains are cleaned up', async () => {
  const r = await owner('POST', '/api/clients', { name: 'Desert Smiles Dental', domain: 'https://www.DesertSmiles.example/home', cms: 'wordpress' });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  clientId = r.data.id;
  const list = (await owner('GET', '/api/clients')).data;
  assert.deepEqual(list.map((c: { domain: string }) => c.domain), ['desertsmiles.example']);
  assert.equal((await owner('POST', '/api/clients', { name: '' })).status, 400);
});

test('adding a new person returns a one-time temporary password', async () => {
  const r = await owner('POST', '/api/team', { fullName: 'Sam Patel', email: 'sam@brightline.example', template: 'seo_specialist' });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.match(r.data.temporaryPassword, /^[A-Za-z0-9_-]{16}$/);
  seoId = r.data.membershipId;
  const dup = await owner('POST', '/api/team', { fullName: 'Sam Patel', email: 'sam@brightline.example', template: 'analyst' });
  assert.equal(dup.status, 400);
  assert.match(dup.data.error, /already on your team/);
});

test('another agency adding an existing person never gets a password for them', async () => {
  const r = await otherOwner('POST', '/api/team', { fullName: 'Dana Ortiz', email: 'dana@brightline.example', template: 'analyst' });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.temporaryPassword, null);
  const r2 = await otherOwner('POST', '/api/team', { fullName: 'Sam Patel', email: 'sam@brightline.example', template: 'analyst' });
  assert.equal(r2.data.temporaryPassword, null, 'a person invited elsewhere but not yet signed in is still protected');
});

test('client roles need a client in your own agency', async () => {
  assert.equal((await owner('POST', '/api/team', { fullName: 'Lena Ruiz', email: 'lena@desertsmiles.example', template: 'client_admin' })).status, 400);
  const theirs = (await otherOwner('POST', '/api/clients', { name: 'Copperline Client' })).data.id;
  const r = await owner('POST', '/api/team', { fullName: 'Lena Ruiz', email: 'lena@desertsmiles.example', template: 'client_admin', clientId: theirs });
  assert.equal(r.status, 400);
  assert.match(r.data.error, /not in your agency/);
  assert.equal((await owner('POST', '/api/team', { fullName: 'Lena Ruiz', email: 'lena@desertsmiles.example', template: 'client_admin', clientId })).status, 200);
});

test('access changes are saved, and client teams can’t get agency-only areas', async () => {
  assert.equal((await owner('POST', `/api/team/${seoId}/access`, { module: 'ads', level: 'view' })).status, 200);
  const team = (await owner('GET', '/api/team')).data;
  assert.equal(team.find((m: { id: string }) => m.id === seoId).access.ads, 'view');
  const lena = team.find((m: { email: string }) => m.email === 'lena@desertsmiles.example');
  const r = await owner('POST', `/api/team/${lena.id}/access`, { module: 'margins', level: 'view' });
  assert.equal(r.status, 400);
  assert.match(r.data.error, /cannot have access to margins/);
});

test('one agency can’t change another agency’s people', async () => {
  const r = await otherOwner('POST', `/api/team/${seoId}/active`, { active: false });
  assert.equal(r.status, 404);
  const r2 = await otherOwner('POST', `/api/team/${seoId}/access`, { module: 'site', level: 'none' });
  assert.equal(r2.status, 400);
});

test('people without team access can’t see the team, add clients or change branding', async () => {
  const temp = issueTemporaryPassword(cfg, personId('sam@brightline.example'), { resetMfa: false }, 't').temporaryPassword;
  const sam = await onboard('sam@brightline.example', temp);
  const me = (await sam('GET', '/auth/me')).data;
  if (!me.workspace) await sam('POST', '/auth/workspace', { membershipId: seoId });
  assert.equal((await sam('GET', '/api/team')).status, 403);
  assert.equal((await sam('POST', '/api/clients', { name: 'Sneaky Client' })).status, 403);
  assert.equal((await sam('POST', '/api/agency/branding', { name: 'Hijacked', brandColor: '#000000' })).status, 403);
  assert.equal((await sam('GET', '/api/clients')).data.length, 1);
});

test('branding changes apply to the agency, and are checked', async () => {
  assert.equal((await owner('POST', '/api/agency/branding', { name: 'Brightline', brandColor: 'red' })).status, 400);
  assert.equal((await owner('POST', '/api/agency/branding', { name: 'Brightline Digital Co', brandColor: '#2557C9', portalDomain: 'portal.brightline.example' })).status, 200);
  const s = (await owner('GET', '/api/session')).data;
  assert.equal(s.agency.brandColor, '#2557C9');
  assert.equal(s.agency.portalDomain, 'portal.brightline.example');
  const clash = await otherOwner('POST', '/api/agency/branding', { name: 'Copperline', brandColor: '#1F2937', portalDomain: 'portal.brightline.example' });
  assert.equal(clash.status, 400);
  assert.match(clash.data.error, /already in use/);
});

test('the activity log shows this agency’s changes only', async () => {
  const a = (await owner('GET', '/api/activity')).data as { actor: string; entity: string }[];
  assert.ok(a.some(x => x.entity === 'clients' && x.actor === 'dana@brightline.example'));
  assert.ok(!a.some(x => x.actor === 'kim@copperline.example'), 'never another agency’s activity');
});
