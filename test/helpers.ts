import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import type { DbConfig } from '../src/db.ts';

export const MIGRATIONS = ['001_core.sql'];

export function psql(c: DbConfig, sql: string): string {
  return execFileSync('psql', ['-X', '-q', '-v', 'ON_ERROR_STOP=1', '-h', c.host, '-p', String(c.port), '-U', c.user, '-d', c.database],
    { input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

/** A throwaway database with every migration applied. */
export function freshDb(tag: string): { cfg: DbConfig; drop: () => void } {
  const cfg: DbConfig = {
    host: process.env.PGHOST ?? '/var/run/postgresql',
    port: Number(process.env.PGPORT ?? 5432),
    user: process.env.PGUSER ?? 'postgres',
    database: `ordix_${tag}_${process.pid}`,
  };
  const admin = { ...cfg, database: 'postgres' };
  psql(admin, `CREATE DATABASE ${cfg.database};`);
  for (const f of MIGRATIONS) psql(cfg, readFileSync(new URL(`../db/${f}`, import.meta.url), 'utf8'));
  return { cfg, drop: () => { psql(admin, `DROP DATABASE IF EXISTS ${cfg.database} WITH (FORCE);`); } };
}

/** Runs fn and returns the database error text it raised (fails the test if nothing was raised). */
export function errorOf(fn: () => unknown): string {
  try { fn(); } catch (e) { return String((e as { stderr?: string }).stderr ?? e); }
  throw new Error('Expected an error, but the call succeeded');
}
