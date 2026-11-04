// The Ordix web app: sign-in (/auth/*), the JSON API (/api/*) and the browser screens (public/).
//
//   PGHOST=... PGDATABASE=ordix SECRETS_KEY=<64 hex> node src/server.ts     (PORT, default 8800)
//
// Production runs behind HTTPS with SECURE_COOKIES=1 and AWS Secrets Manager in place of the local store.
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createAuth, AuthError } from './auth.ts';
import { createApi } from './api.ts';
import { LocalEncryptedStore, type SecretStore } from './secrets.ts';
import type { DbConfig } from './db.ts';

const STATIC: Record<string, [string, string]> = {
  '/': ['app.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/app.css': ['app.css', 'text/css; charset=utf-8'],
};
const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'",
};

export function createAppServer(o: { db: DbConfig; secrets: SecretStore; secureCookies?: boolean }): Server {
  const auth = createAuth({ db: o.db, secrets: o.secrets, secureCookies: o.secureCookies });
  const api = createApi({ db: o.db });
  const files = new Map(Object.entries(STATIC).map(([route, [file, type]]) =>
    [route, { body: readFileSync(new URL(`../public/${file}`, import.meta.url)), type }]));

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    const send = (code: number, data: unknown) => {
      res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(data));
    };
    try {
      const f = files.get(path);
      if (f && req.method === 'GET') { res.writeHead(200, { 'content-type': f.type, 'cache-control': 'no-cache' }); res.end(f.body); return; }
      if (await auth.handle(req, res, path)) return;
      if (path.startsWith('/api/')) return send(200, await api.handle(req, res, path, auth.require(req)));
      send(404, { error: 'Not found' });
    } catch (e) {
      const err = e instanceof AuthError ? e : new AuthError(500, 'Something went wrong. Try again.');
      if (!(e instanceof AuthError)) console.error(e);
      send(err.status, { error: err.message });
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const db: DbConfig = { host: process.env.PGHOST ?? '/var/run/postgresql', port: Number(process.env.PGPORT ?? 5432),
    user: process.env.PGUSER ?? 'postgres', database: process.env.PGDATABASE ?? 'ordix' };
  const key = process.env.SECRETS_KEY ?? '';
  const secrets = new LocalEncryptedStore(process.env.SECRETS_FILE ?? '.secrets.json', key);
  const port = Number(process.env.PORT ?? 8800);
  createAppServer({ db, secrets, secureCookies: process.env.SECURE_COOKIES === '1' })
    .listen(port, process.env.HOST ?? '127.0.0.1', () => console.log(`Ordix at http://127.0.0.1:${port}`));
}
