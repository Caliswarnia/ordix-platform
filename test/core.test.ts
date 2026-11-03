import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { freshDb, psql, errorOf } from './helpers.ts';
import { query, asMember } from '../src/db.ts';
import { createAgency, addClient, addMember, setAccess, myAccess, visibleClients } from '../src/access.ts';

const { cfg, drop } = freshDb('core');
after(drop);

let a: { agencyId: string; ownerMembershipId: string };
let b: { agencyId: string; ownerMembershipId: string };
let dental = '', roofing = '', otherAgencyClient = '';
let seo = '', clientAdmin = '';

before(() => {
  a = createAgency(cfg, { name: 'Brightline Digital', slug: 'brightline', ownerEmail: 'dana@brightline.example', ownerName: 'Dana Ortiz' }, 'ordix:test');
  b = createAgency(cfg, { name: 'Copperline Marketing', slug: 'copperline', ownerEmail: 'kim@copperline.example', ownerName: 'Kim Lee' }, 'ordix:test');
  dental = addClient(cfg, a.ownerMembershipId, 'dana@brightline.example', { name: 'Desert Smiles Dental', domain: 'desertsmiles.example', cms: 'wordpress' });
  roofing = addClient(cfg, a.ownerMembershipId, 'dana@brightline.example', { name: 'Mesa Ridge Roofing', domain: 'mesaridge.example', cms: 'webflow' });
  otherAgencyClient = addClient(cfg, b.ownerMembershipId, 'kim@copperline.example', { name: 'Other Agency Client' });
  seo = addMember(cfg, a.ownerMembershipId, 'dana@brightline.example', { email: 'sam@brightline.example', fullName: 'Sam Patel', template: 'seo_specialist' });
  clientAdmin = addMember(cfg, a.ownerMembershipId, 'dana@brightline.example', { email: 'lena@desertsmiles.example', fullName: 'Lena Ruiz', template: 'client_admin', clientId: dental });
});

test('owners have full access to every area', () => {
  const acc = myAccess(cfg, a.ownerMembershipId);
  assert.ok(Object.values(acc).every(l => l === 'approve'));
});

test('templates set the starting access, and unlisted areas are none', () => {
  const acc = myAccess(cfg, seo);
  assert.equal(acc.site, 'edit');
  assert.equal(acc.ads, 'none');
  assert.equal(acc.margins, 'none');
});

test('an agency sees only its own clients', () => {
  const names = visibleClients(cfg, a.ownerMembershipId).map(c => c.name);
  assert.deepEqual(names, ['Desert Smiles Dental', 'Mesa Ridge Roofing']);
  assert.ok(!visibleClients(cfg, a.ownerMembershipId).some(c => c.id === otherAgencyClient));
});

test('a client-level person sees only their own client', () => {
  assert.deepEqual(visibleClients(cfg, clientAdmin).map(c => c.id), [dental]);
});

test('client-level people can never be given margins, team or branding access', () => {
  const err = errorOf(() => setAccess(cfg, a.ownerMembershipId, 'dana@brightline.example', clientAdmin, 'margins', 'view'));
  assert.match(err, /cannot have access to margins/);
});

test('only people with team edit access can add people', () => {
  const err = errorOf(() => addMember(cfg, seo, 'sam@brightline.example', { email: 'x@brightline.example', fullName: 'X Person', template: 'analyst' }));
  assert.match(err, /need edit access to Team and roles/);
});

test('an agency cannot add a person to another agency’s client', () => {
  const err = errorOf(() => addMember(cfg, a.ownerMembershipId, 'dana@brightline.example', { email: 'y@example.com', fullName: 'Y Person', template: 'client_viewer', clientId: otherAgencyClient }));
  assert.match(err, /not in your agency/);
});

test('an agency cannot change another agency’s people', () => {
  const changed = asMember<number>(cfg, b.ownerMembershipId, 'kim@copperline.example', `
    WITH u AS (UPDATE memberships SET title = 'Hacked' WHERE id = :'t'::uuid RETURNING 1) SELECT count(*) FROM u;`, { t: seo });
  assert.equal(changed, 0);
});

test('an agency always keeps an active owner', () => {
  const err = errorOf(() => psql(cfg, `UPDATE memberships SET active = false WHERE id = '${a.ownerMembershipId}';`));
  assert.match(err, /must keep at least one active owner/);
});

test('ownership can be handed over inside one transaction', () => {
  psql(cfg, `BEGIN;
    UPDATE memberships SET is_owner = true WHERE id = '${seo}';
    UPDATE memberships SET is_owner = false WHERE id = '${a.ownerMembershipId}';
    COMMIT;`);
  assert.equal(myAccess(cfg, seo).margins, 'approve');
  psql(cfg, `BEGIN;
    UPDATE memberships SET is_owner = true WHERE id = '${a.ownerMembershipId}';
    UPDATE memberships SET is_owner = false WHERE id = '${seo}';
    COMMIT;`);
});

test('a suspended agency loses all access, and ended is final', () => {
  psql(cfg, `UPDATE agencies SET status = 'suspended', status_reason = 'Unpaid invoice' WHERE id = '${b.agencyId}';`);
  assert.deepEqual(visibleClients(cfg, b.ownerMembershipId), []);
  psql(cfg, `UPDATE agencies SET status = 'ended', status_reason = 'Closed account' WHERE id = '${b.agencyId}';`);
  const err = errorOf(() => psql(cfg, `UPDATE agencies SET status = 'active', status_reason = null WHERE id = '${b.agencyId}';`));
  assert.match(err, /cannot be reactivated/);
});

test('changes are in the audit log with who made them, and the log is append-only', () => {
  const rows = query<{ actor: string }[]>(cfg, `SELECT json_agg(json_build_object('actor', actor)) FROM audit_log WHERE entity = 'clients' AND agency_id = '${a.agencyId}';`);
  assert.ok(rows.every(r => r.actor === 'dana@brightline.example'));
  assert.match(errorOf(() => psql(cfg, `DELETE FROM audit_log;`)), /append-only/);
});

test('agency staff without team access cannot read the audit log', () => {
  const n = asMember<number>(cfg, seo, 'sam@brightline.example', `SELECT count(*) FROM audit_log;`);
  assert.equal(n, 0);
});
