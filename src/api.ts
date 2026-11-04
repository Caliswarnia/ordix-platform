// JSON API for the agency and client screens. Every request runs as the signed-in member
// (asMember), so row-level security decides what each person sees; these handlers add
// friendly checks and messages on top, never instead.
//
//   GET  /api/session                     who you are, your workspace, your access, your agency's branding
//   GET  /api/clients                     clients you can see
//   POST /api/clients                     { name, domain, cms }                         team: edit
//   GET  /api/team                        people and their access                       team: view
//   POST /api/team                        { email, fullName, template, clientId? }      team: edit
//   POST /api/team/:id/access             { module, level }                             team: edit
//   POST /api/team/:id/active             { active }                                    team: edit
//   POST /api/agency/branding             { name, brandColor, portalDomain }            branding: edit
//   GET  /api/activity                    recent changes                                team: view
//   GET  /api/clients/:id/connections     connected accounts for a client               accounts: view
//   POST /api/clients/:id/connections/google   -> { url } to send the browser to Google   accounts: edit
//   POST /api/connections/:id/disconnect                                                accounts: edit
//   POST /api/properties/:id/select       which site/property feeds the dashboards      accounts: edit
//   GET  /api/clients/:id/seo             Search Console and Analytics numbers          seo: view
//   GET  /api/agency/oauth-app            whether the agency uses its own Google app    team: view
//   POST /api/agency/oauth-app            { provider, clientId, clientSecret }           owner only
import type { IncomingMessage, ServerResponse } from 'node:http';
import { query, asMember, type DbConfig } from './db.ts';
import { AuthError, issueTemporaryPassword, type SignedIn, type Workspace } from './auth.ts';
import { addClient, addMember, setAccess, TEMPLATES, type Level, type Module } from './access.ts';
import type { Connections } from './connections.ts';

type Member = SignedIn & { workspace: Workspace };
const LEVELS = ['none', 'view', 'edit', 'approve'];
const MODULES = ['seo', 'site', 'ads', 'social', 'reports', 'accounts', 'margins', 'team', 'branding'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function dbMessage(e: unknown, fallback: string): string {
  const m = String((e as { stderr?: string }).stderr ?? '').match(/ERROR:\s+(.*)/);
  if (!m) return fallback;
  const msg = m[1].trim();
  if (/duplicate key value.*memberships_agency_id_person_id/.test(msg)) return 'That person is already on your team';
  if (/violates check constraint "clients_domain_check"/.test(msg)) return 'Enter a domain like example.com';
  if (/violates check constraint "agencies_portal_domain_check"/.test(msg)) return 'Enter a portal address like portal.youragency.com';
  if (/duplicate key value.*agencies_portal_domain_key/.test(msg)) return 'That portal address is already in use';
  if (/violates (check|not-null|foreign key|unique)/.test(msg)) return fallback;
  return msg;
}

export function createApi(o: { db: DbConfig; connections: Connections }) {
  const as = <T>(m: Member, sql: string, vars: Record<string, string> = {}) => asMember<T>(o.db, m.workspace.membershipId, m.email, sql, vars);
  const access = (m: Member) => as<Record<Module, Level>>(m, `SELECT json_object_agg(module, level) FROM v_my_access;`);
  const need = (m: Member, mod: Module, lvl: Level) => {
    if (LEVELS.indexOf(access(m)[mod]) < LEVELS.indexOf(lvl)) throw new AuthError(403, 'Your role doesn’t allow this');
  };

  async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
    let raw = '';
    for await (const c of req) { raw += c; if (raw.length > 1e5) throw new AuthError(413, 'Request too large'); }
    try { return raw ? JSON.parse(raw) : {}; } catch { throw new AuthError(400, 'Body must be JSON'); }
  }
  const str = (b: Record<string, unknown>, k: string, max = 200) => (typeof b[k] === 'string' ? (b[k] as string).trim().slice(0, max) : '');

  /** Handles /api/*; the caller has already required a signed-in member. */
  async function handle(req: IncomingMessage, res: ServerResponse, path: string, m: Member): Promise<unknown> {
    const method = req.method ?? 'GET';
    const parts = path.split('/').filter(Boolean);   // ['api', ...]

    if (method === 'GET' && path === '/api/session') {
      const agency = as<{ name: string; brandColor: string; portalDomain: string | null; slug: string }>(m,
        `SELECT json_build_object('name', name, 'slug', slug, 'brandColor', brand_color, 'portalDomain', portal_domain) FROM agencies;`);
      return { person: { email: m.email, fullName: m.fullName }, workspace: m.workspace, workspaces: m.workspaces, access: access(m), agency,
               templates: Object.entries(TEMPLATES).map(([key, t]) => ({ key, title: t.title, clientLevel: t.clientLevel })) };
    }

    if (method === 'GET' && path === '/api/clients') {
      return as(m, `SELECT coalesce(json_agg(json_build_object('id', id, 'name', name, 'domain', domain, 'cms', cms) ORDER BY name), '[]')
                    FROM clients WHERE archived_at IS NULL;`);
    }
    if (method === 'POST' && path === '/api/clients') {
      need(m, 'team', 'edit');
      const b = await body(req);
      const name = str(b, 'name', 120);
      if (!name) throw new AuthError(400, 'Enter the client’s name');
      const cms = ['wordpress', 'webflow', 'other'].includes(str(b, 'cms')) ? str(b, 'cms') as 'wordpress' | 'webflow' | 'other' : 'other';
      const domain = str(b, 'domain').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
      try { return { id: addClient(o.db, m.workspace.membershipId, m.email, { name, domain, cms }) }; }
      catch (e) { throw new AuthError(400, dbMessage(e, 'Check the client details')); }
    }

    if (method === 'GET' && path === '/api/team') {
      need(m, 'team', 'view');
      return as(m, `
        SELECT coalesce(json_agg(json_build_object(
          'id', mb.id, 'name', p.full_name, 'email', p.email, 'title', mb.title, 'isOwner', mb.is_owner, 'active', mb.active,
          'clientId', mb.client_id, 'client', c.name,
          'access', (SELECT json_object_agg(mo.code, access_level(mb.id, mo.code)) FROM modules mo)
        ) ORDER BY mb.is_owner DESC, mb.client_id NULLS FIRST, p.full_name), '[]')
        FROM memberships mb JOIN people p ON p.id = mb.person_id LEFT JOIN clients c ON c.id = mb.client_id;`);
    }
    if (method === 'POST' && path === '/api/team') {
      need(m, 'team', 'edit');
      const b = await body(req);
      const email = str(b, 'email').toLowerCase(), fullName = str(b, 'fullName', 120), template = str(b, 'template');
      const clientId = str(b, 'clientId');
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new AuthError(400, 'Enter a valid email');
      if (!fullName) throw new AuthError(400, 'Enter their name');
      if (!TEMPLATES[template]) throw new AuthError(400, 'Choose a role');
      if (TEMPLATES[template].clientLevel && !UUID.test(clientId)) throw new AuthError(400, 'Choose which client they work for');
      let membershipId: string;
      try {
        membershipId = addMember(o.db, m.workspace.membershipId, m.email, { email, fullName, template, clientId: TEMPLATES[template].clientLevel ? clientId : undefined });
      } catch (e) { throw new AuthError(400, dbMessage(e, 'Check the details and try again')); }
      // A brand-new person gets a one-time temporary password to pass on (until invite emails exist).
      // Anyone already known to Ordix (a login, or a place in any other agency) keeps their own
      // sign-in untouched: one agency must never be able to set a password for another agency's person.
      const personId = query<string>(o.db, `SELECT to_json(person_id) FROM memberships WHERE id = :'m'::uuid;`, { m: membershipId });
      const isNew = query<boolean>(o.db, `SELECT to_json(NOT EXISTS (SELECT 1 FROM person_sign_in WHERE person_id = :'p'::uuid)
          AND (SELECT count(*) FROM memberships WHERE person_id = :'p'::uuid) = 1);`, { p: personId });
      const temporaryPassword = isNew ? issueTemporaryPassword(o.db, personId, { resetMfa: false }, m.email).temporaryPassword : null;
      return { membershipId, temporaryPassword };
    }
    if (method === 'POST' && parts[1] === 'team' && UUID.test(parts[2] ?? '') && (parts[3] === 'access' || parts[3] === 'active') && parts.length === 4) {
      need(m, 'team', 'edit');
      const b = await body(req);
      const target = parts[2];
      if (target === m.workspace.membershipId && parts[3] === 'active') throw new AuthError(400, 'You can’t deactivate yourself');
      try {
        if (parts[3] === 'access') {
          const mod = str(b, 'module'), lvl = str(b, 'level');
          if (!MODULES.includes(mod) || !LEVELS.includes(lvl)) throw new AuthError(400, 'Choose an area and a level');
          setAccess(o.db, m.workspace.membershipId, m.email, target, mod as Module, lvl as Level);
        } else {
          const n = as<number>(m, `WITH u AS (UPDATE memberships SET active = :'a'::boolean WHERE id = :'t'::uuid RETURNING 1) SELECT count(*) FROM u;`,
            { a: String(b.active === true), t: target });
          if (!n) throw new AuthError(404, 'Person not found');
        }
      } catch (e) { if (e instanceof AuthError) throw e; throw new AuthError(400, dbMessage(e, 'That change isn’t allowed')); }
      return { ok: true };
    }

    if (method === 'POST' && path === '/api/agency/branding') {
      need(m, 'branding', 'edit');
      const b = await body(req);
      const name = str(b, 'name', 80), color = str(b, 'brandColor'), portal = str(b, 'portalDomain').toLowerCase();
      if (!name) throw new AuthError(400, 'Enter your agency’s name');
      if (!/^#[0-9A-Fa-f]{6}$/.test(color)) throw new AuthError(400, 'Choose a color');
      try {
        as(m, `UPDATE agencies SET name = :'n', brand_color = :'c', portal_domain = nullif(:'p', '') WHERE id = current_agency_id(); SELECT 'null'::json;`,
          { n: name, c: color, p: portal });
      } catch (e) { throw new AuthError(400, dbMessage(e, 'Check the branding details')); }
      return { ok: true };
    }

    if (method === 'GET' && path === '/api/activity') {
      need(m, 'team', 'view');
      return as(m, `SELECT coalesce(json_agg(r), '[]') FROM (
        SELECT at, actor, action, entity, entity_id AS "entityId",
          CASE WHEN entity = 'memberships' THEN (SELECT full_name FROM people WHERE id = (coalesce(after, before) ->> 'person_id')::uuid)
               WHEN entity = 'membership_access' THEN (SELECT p.full_name FROM memberships mb JOIN people p ON p.id = mb.person_id
                                                        WHERE mb.id = (coalesce(after, before) ->> 'membership_id')::uuid)
               ELSE coalesce(after ->> 'name', before ->> 'name') END AS label,
          coalesce(after ->> 'title', before ->> 'title') AS title,
          CASE WHEN action = 'update' THEN (SELECT json_agg(k) FROM jsonb_object_keys(after) k WHERE after -> k IS DISTINCT FROM before -> k) END AS changed,
          after ->> 'module' AS module, after ->> 'level' AS level
        FROM audit_log ORDER BY id DESC LIMIT 100) r;`);
    }

    // Connected accounts
    if (parts[1] === 'clients' && UUID.test(parts[2] ?? '')) {
      const clientId = parts[2];
      if (method === 'GET' && parts[3] === 'connections' && parts.length === 4) { need(m, 'accounts', 'view'); return o.connections.list(m, clientId); }
      if (method === 'POST' && parts[3] === 'connections' && parts[4] === 'google' && parts.length === 5) return { url: o.connections.startGoogle(m, clientId) };
      if (method === 'GET' && parts[3] === 'seo' && parts.length === 4) return o.connections.seo(m, clientId);
    }
    if (method === 'POST' && parts[1] === 'connections' && UUID.test(parts[2] ?? '') && parts[3] === 'disconnect' && parts.length === 4) {
      await o.connections.disconnect(m, parts[2]); return { ok: true };
    }
    if (method === 'POST' && parts[1] === 'properties' && UUID.test(parts[2] ?? '') && parts[3] === 'select' && parts.length === 4) {
      o.connections.selectProperty(m, parts[2]); return { ok: true };
    }
    if (path === '/api/agency/oauth-app') {
      if (method === 'GET') {
        need(m, 'team', 'view');
        return as(m, `SELECT coalesce(json_agg(json_build_object('provider', provider, 'clientId', app_client_id, 'since', created_at)), '[]') FROM oauth_apps;`);
      }
      if (method === 'POST') {
        const b = await body(req);
        const provider = str(b, 'provider');
        if (provider !== 'google' && provider !== 'meta') throw new AuthError(400, 'Choose Google or Meta');
        o.connections.saveAgencyApp(m, provider, str(b, 'clientId', 300), str(b, 'clientSecret', 500));
        return { ok: true };
      }
    }

    throw new AuthError(404, 'Not found');
  }

  return { handle };
}
