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
import { createConnections } from './connections.ts';
import { createGoogle, type Google } from './google.ts';
import { createMeta, type Meta } from './meta.ts';
import type { DbConfig } from './db.ts';

const STATIC: Record<string, [string, string]> = {
  '/': ['app.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/app.css': ['app.css', 'text/css; charset=utf-8'],
  '/oauth/google/callback': ['oauth.html', 'text/html; charset=utf-8'],
  '/oauth/meta/callback': ['oauth.html', 'text/html; charset=utf-8'],
  '/oauth.js': ['oauth.js', 'text/javascript; charset=utf-8'],
};
const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'",
};

export interface AppOptions {
  db: DbConfig; secrets: SecretStore; secureCookies?: boolean;
  publicUrl?: string;                                     // e.g. https://app.ordixit.com
  google?: Google; meta?: Meta;                           // injected in tests
  googleApp?: { clientId: string; clientSecret: string }; // Ordix's own Google OAuth app
  metaApp?: { clientId: string; clientSecret: string };   // Ordix's own Meta app
}

export function createAppServer(o: AppOptions): Server {
  const auth = createAuth({ db: o.db, secrets: o.secrets, secureCookies: o.secureCookies });
  const connections = createConnections({ db: o.db, secrets: o.secrets, google: o.google ?? createGoogle(), meta: o.meta ?? createMeta(),
    googleApp: o.googleApp, metaApp: o.metaApp,
    publicUrl: o.publicUrl ?? 'http://127.0.0.1:8800' });
  const api = createApi({ db: o.db, connections });
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
      // The provider sends the browser back to /oauth/<provider>/callback (a page that needs no session, because
      // SameSite=Strict cookies aren't sent on that cross-site return); its script then posts here, same-site.
      const fin = path.match(/^\/oauth\/(google|meta)\/finish$/);
      if (fin && req.method === 'POST') {
        if (req.headers['x-requested-with'] !== 'ordix') throw new AuthError(403, 'Missing request header');
        let raw = ''; for await (const c of req) { raw += c; if (raw.length > 1e4) throw new AuthError(413, 'Request too large'); }
        const params = new URLSearchParams(String(JSON.parse(raw || '{}').query ?? '').replace(/^\?/, ''));
        return send(200, { clientId: await connections.finish(fin[1] as 'google' | 'meta', auth.current(req), params) });
      }
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
  const googleApp = process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
    ? { clientId: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET } : undefined;
  const metaApp = process.env.META_APP_ID && process.env.META_APP_SECRET
    ? { clientId: process.env.META_APP_ID, clientSecret: process.env.META_APP_SECRET } : undefined;
  createAppServer({ db, secrets, secureCookies: process.env.SECURE_COOKIES === '1', publicUrl: process.env.PUBLIC_URL, googleApp, metaApp })
    .listen(port, process.env.HOST ?? '127.0.0.1', () => console.log(`Ordix at http://127.0.0.1:${port}`));
}
