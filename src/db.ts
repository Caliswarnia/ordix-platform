// Minimal database access through the psql client (no npm packages needed yet).
// psql quotes every :'var' substitution itself, so values are never spliced into SQL by hand.
// Swap for the `pg` driver when the web server lands.
import { execFileSync } from 'node:child_process';

export interface DbConfig { host: string; port: number; user: string; database: string; }

export function query<T = unknown>(cfg: DbConfig, sql: string, vars: Record<string, string> = {}): T {
  const args = ['-X', '-q', '-tA', '-v', 'ON_ERROR_STOP=1',
    '-h', cfg.host, '-p', String(cfg.port), '-U', cfg.user, '-d', cfg.database];
  for (const [k, v] of Object.entries(vars)) args.push('-v', `${k}=${v}`);
  const out = execFileSync('psql', args, { input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  return (out ? JSON.parse(out) : null) as T;
}

/** Runs `sql` as a signed-in member: row-level security limits every row to their agency (and client). */
export function asMember<T = unknown>(cfg: DbConfig, membershipId: string, actor: string, sql: string, vars: Record<string, string> = {}): T {
  return query<T>(cfg, `
    BEGIN;
    SELECT set_config('app.membership_id', :'__mid', true), set_config('app.actor', :'__actor', true) \\g /dev/null
    SET LOCAL ROLE ordix_member;
    ${sql}
    COMMIT;`, { ...vars, __mid: membershipId, __actor: actor });
}
