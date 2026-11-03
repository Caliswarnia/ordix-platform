// Agencies, clients, people and access levels.
// Platform actions (creating an agency) run as the database owner; everything an agency
// does runs through asMember, so row-level security keeps each agency to its own data.
import { query, asMember, type DbConfig } from './db.ts';

export type Level = 'none' | 'view' | 'edit' | 'approve';
export type Module = 'seo' | 'site' | 'ads' | 'social' | 'reports' | 'accounts' | 'margins' | 'team' | 'branding';
export type Access = Partial<Record<Module, Level>>;

/** Starting points an agency picks from when adding someone; every area can be changed afterwards. */
export const TEMPLATES: Record<string, { title: string; clientLevel: boolean; access: Access }> = {
  account_manager: { title: 'Account manager', clientLevel: false,
    access: { seo: 'view', site: 'view', ads: 'view', social: 'approve', reports: 'edit', accounts: 'view', margins: 'view', team: 'view' } },
  seo_specialist: { title: 'SEO specialist', clientLevel: false,
    access: { seo: 'edit', site: 'edit', reports: 'view', accounts: 'view' } },
  media_buyer: { title: 'Media buyer', clientLevel: false,
    access: { ads: 'edit', social: 'edit', reports: 'view', accounts: 'view' } },
  analyst: { title: 'Analyst', clientLevel: false,
    access: { seo: 'view', site: 'view', ads: 'view', social: 'view', reports: 'view' } },
  client_admin: { title: 'Client admin', clientLevel: true,
    access: { seo: 'view', site: 'approve', ads: 'view', social: 'approve', reports: 'view', accounts: 'edit' } },
  client_viewer: { title: 'Client viewer', clientLevel: true,
    access: { seo: 'view', ads: 'view', social: 'view', reports: 'view' } },
};

export interface NewAgency { name: string; slug: string; ownerEmail: string; ownerName: string; }

/** Ordix staff only: creates an agency together with its first owner, in one transaction. */
export function createAgency(cfg: DbConfig, a: NewAgency, actor: string): { agencyId: string; ownerMembershipId: string } {
  return query(cfg, `
    BEGIN;
    SELECT set_config('app.actor', :'actor', true) \\g /dev/null
    WITH ag AS (INSERT INTO agencies (name, slug) VALUES (btrim(:'name'), lower(:'slug')) RETURNING id),
         pe AS (INSERT INTO people (email, full_name) VALUES (lower(btrim(:'email')), btrim(:'owner'))
                ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id),
         me AS (INSERT INTO memberships (agency_id, person_id, title, is_owner)
                SELECT ag.id, pe.id, 'Owner', true FROM ag, pe RETURNING id, agency_id)
    SELECT json_build_object('agencyId', agency_id, 'ownerMembershipId', id) FROM me;
    COMMIT;`, { actor, name: a.name, slug: a.slug, email: a.ownerEmail, owner: a.ownerName });
}

export function addClient(cfg: DbConfig, memberId: string, actor: string, c: { name: string; domain?: string; cms?: 'wordpress' | 'webflow' | 'other' }): string {
  return asMember<string>(cfg, memberId, actor, `
    INSERT INTO clients (agency_id, name, domain, cms)
      VALUES (current_agency_id(), btrim(:'name'), nullif(lower(btrim(:'domain')), ''), :'cms')
      RETURNING to_json(id);`, { name: c.name, domain: c.domain ?? '', cms: c.cms ?? 'other' });
}

export function addMember(cfg: DbConfig, memberId: string, actor: string,
  p: { email: string; fullName: string; template: keyof typeof TEMPLATES; clientId?: string; title?: string; access?: Access }): string {
  const t = TEMPLATES[p.template];
  if (!t) throw new Error(`Unknown template: ${p.template}`);
  if (t.clientLevel !== Boolean(p.clientId)) throw new Error(t.clientLevel ? 'Client roles need a client' : 'Agency roles cannot have a client');
  return asMember<string>(cfg, memberId, actor, `
    SELECT to_json(add_member(:'email', :'name', :'title', nullif(:'client', '')::uuid, :'access'::jsonb));`,
    { email: p.email, name: p.fullName, title: p.title ?? t.title, client: p.clientId ?? '', access: JSON.stringify({ ...t.access, ...p.access }) });
}

export function setAccess(cfg: DbConfig, memberId: string, actor: string, targetMembershipId: string, module: Module, level: Level): void {
  asMember(cfg, memberId, actor, `
    INSERT INTO membership_access (membership_id, agency_id, module, level)
      VALUES (:'target'::uuid, current_agency_id(), :'module', :'level')
      ON CONFLICT (membership_id, module) DO UPDATE SET level = EXCLUDED.level;`,
    { target: targetMembershipId, module, level });
}

export function myAccess(cfg: DbConfig, memberId: string): Record<Module, Level> {
  return asMember(cfg, memberId, 'read', `SELECT json_object_agg(module, level) FROM v_my_access;`);
}

export function visibleClients(cfg: DbConfig, memberId: string): { id: string; name: string }[] {
  return asMember(cfg, memberId, 'read', `SELECT coalesce(json_agg(json_build_object('id', id, 'name', name) ORDER BY name), '[]') FROM clients;`);
}
