// Applies database migrations (db/NNN_*.sql) that haven't run yet, in order, each in its own
// transaction, and records them in schema_migrations. Safe to run on every deploy.
//
//   node src/migrate.ts            uses PGHOST / PGPORT / PGUSER / PGPASSWORD / PGDATABASE
import { readdirSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const dir = new URL('../db/', import.meta.url);
const args = ['-X', '-q', '-tA', '-v', 'ON_ERROR_STOP=1'];
const psql = (sql: string) => execFileSync('psql', args, { input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'inherit'] }).trim();

psql(`SET client_min_messages = warning; CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());`);
const done = new Set(psql(`SELECT name FROM schema_migrations;`).split('\n').filter(Boolean));
const files = readdirSync(dir).filter(f => /^\d{3}_.+\.sql$/.test(f)).sort();
let n = 0;
for (const f of files) {
  if (done.has(f)) continue;
  const body = readFileSync(new URL(f, dir), 'utf8');
  psql(`BEGIN;\n${body}\n;INSERT INTO schema_migrations (name) VALUES ('${f.replace(/'/g, "''")}');\nCOMMIT;`);
  console.log(`Applied ${f}`);
  n++;
}
console.log(n ? `${n} migration(s) applied.` : 'Database is up to date.');
