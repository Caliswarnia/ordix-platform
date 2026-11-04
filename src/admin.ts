// Ordix staff tasks from the command line (runs as the database owner, outside row-level security).
//
//   node src/admin.ts create-agency --name "Echelon Staffing Solutions" --slug echelon --owner-email you@example.com --owner-name "Your Name"
//   node src/admin.ts reset --email someone@example.com [--mfa]       new temporary password; --mfa also clears the authenticator
//   node src/admin.ts suspend --slug echelon --reason "Unpaid invoice"
//   node src/admin.ts reactivate --slug echelon
//
// Prints one-time temporary passwords; each person sets up an authenticator and their own password at first sign-in.
// Recorded in the audit log as ordix:cli. Uses PGHOST / PGPORT / PGUSER / PGDATABASE.
import { parseArgs } from 'node:util';
import { query, type DbConfig } from './db.ts';
import { createAgency } from './access.ts';
import { issueTemporaryPassword } from './auth.ts';

const { positionals, values: v } = parseArgs({ allowPositionals: true, options: {
  name: { type: 'string' }, slug: { type: 'string' }, 'owner-email': { type: 'string' }, 'owner-name': { type: 'string' },
  email: { type: 'string' }, mfa: { type: 'boolean' }, reason: { type: 'string' },
} });
const db: DbConfig = { host: process.env.PGHOST ?? '/var/run/postgresql', port: Number(process.env.PGPORT ?? 5432),
  user: process.env.PGUSER ?? 'postgres', database: process.env.PGDATABASE ?? 'ordix' };
const actor = 'ordix:cli';
const fail = (m: string): never => { console.error(m); process.exit(1); };

switch (positionals[0]) {
  case 'create-agency': {
    if (!v.name || !v.slug || !v['owner-email'] || !v['owner-name']) fail('Use --name --slug --owner-email --owner-name');
    const a = createAgency(db, { name: v.name!, slug: v.slug!, ownerEmail: v['owner-email']!, ownerName: v['owner-name']! }, actor);
    const person = query<string>(db, `SELECT to_json(person_id) FROM memberships WHERE id = :'m'::uuid;`, { m: a.ownerMembershipId });
    const has = query<boolean>(db, `SELECT to_json(EXISTS (SELECT 1 FROM person_sign_in WHERE person_id = :'p'::uuid));`, { p: person });
    console.log(`Created ${v.name} (${v.slug}).`);
    if (has) console.log(`${v['owner-email']} already has an Ordix login and will see the new workspace at next sign-in.`);
    else console.log(`Owner ${v['owner-email']} temporary password (works once): ${issueTemporaryPassword(db, person, { resetMfa: false }, actor).temporaryPassword}`);
    break;
  }
  case 'reset': {
    if (!v.email) fail('Use --email');
    const person = query<string | null>(db, `SELECT to_json(id) FROM people WHERE email = lower(:'e');`, { e: v.email! });
    if (!person) fail(`No one with ${v.email}`);
    const r = issueTemporaryPassword(db, person!, { resetMfa: v.mfa === true }, actor);
    console.log(`Reset ${v.email}${v.mfa ? ' (authenticator too)' : ''}. Temporary password (works once): ${r.temporaryPassword}`);
    break;
  }
  case 'suspend':
  case 'reactivate': {
    if (!v.slug) fail('Use --slug');
    if (positionals[0] === 'suspend' && !v.reason) fail('Suspending needs --reason');
    const r = query(db, `BEGIN; SELECT set_config('app.actor', :'actor', true) \\g /dev/null
      UPDATE agencies SET status = :'st', status_reason = nullif(:'reason', '') WHERE slug = lower(:'slug') RETURNING to_json(name); COMMIT;`,
      { actor, st: positionals[0] === 'suspend' ? 'suspended' : 'active', reason: v.reason ?? '', slug: v.slug! });
    if (!r) fail(`No agency ${v.slug}`);
    console.log(`${r} is now ${positionals[0] === 'suspend' ? 'suspended' : 'active'}.`);
    break;
  }
  default:
    fail('Use: create-agency | reset | suspend | reactivate');
}
