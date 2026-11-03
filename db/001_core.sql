-- Ordix core: agencies (white-label tenants), their clients, people, access levels and the audit log.
--
-- Rules the database enforces (not only the app):
--   - the audit log is append-only; every change to the tables below is recorded with its actor
--   - an agency always keeps at least one active owner, so it can't be locked out
--   - owners are agency-level; client-level people never get access to margins or team settings
--   - a client-level person belongs to exactly one client of that agency
--   - access is per area (module): none, view, edit, approve
--   - row-level security: requests run as ordix_member and see only their own agency,
--     and client-level people only their own client
-- Sign-in (password + authenticator code) follows in 002.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Audit log (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  id         bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  actor      text NOT NULL,
  agency_id  uuid,
  action     text NOT NULL CHECK (action IN ('insert','update','delete')),
  entity     text NOT NULL,
  entity_id  text,
  before     jsonb,
  after      jsonb
);
CREATE INDEX audit_log_agency_at ON audit_log (agency_id, at DESC);

CREATE FUNCTION forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION forbid_change();

-- TG_ARGV[0] = id column, TG_ARGV[1] = agency id column (optional)
CREATE FUNCTION audit_row_change() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_actor  text := coalesce(nullif(current_setting('app.actor', true), ''), 'system:unknown');
  v_row    jsonb := to_jsonb(CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END);
  v_agency uuid := CASE WHEN TG_NARGS > 1 THEN (v_row ->> TG_ARGV[1])::uuid END;
BEGIN
  INSERT INTO audit_log (actor, agency_id, action, entity, entity_id, before, after)
  VALUES (v_actor, v_agency, lower(TG_OP), TG_TABLE_NAME, v_row ->> TG_ARGV[0],
          CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
          CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END);
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $$;

-- ---------------------------------------------------------------------------
-- Agencies (white-label tenants) and their branding
-- ---------------------------------------------------------------------------
CREATE TABLE agencies (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           text NOT NULL CHECK (btrim(name) <> ''),
  slug           text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$'),
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','ended')),
  status_reason  text,
  brand_color    text NOT NULL DEFAULT '#0A7A6A' CHECK (brand_color ~ '^#[0-9A-Fa-f]{6}$'),
  portal_domain  text UNIQUE CHECK (portal_domain IS NULL OR portal_domain ~ '^[a-z0-9.-]+\.[a-z]{2,}$'),
  email_sender   text CHECK (email_sender IS NULL OR email_sender ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT status_change_has_reason CHECK (status = 'active' OR btrim(coalesce(status_reason, '')) <> '')
);
CREATE TRIGGER agencies_audit AFTER INSERT OR UPDATE OR DELETE ON agencies
  FOR EACH ROW EXECUTE FUNCTION audit_row_change('id', 'id');

-- Ended is final.
CREATE FUNCTION agency_status_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'ended' AND NEW.status <> 'ended' THEN
    RAISE EXCEPTION 'An ended agency cannot be reactivated' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER agencies_status_guard BEFORE UPDATE OF status ON agencies
  FOR EACH ROW EXECUTE FUNCTION agency_status_guard();

-- ---------------------------------------------------------------------------
-- Clients of an agency
-- ---------------------------------------------------------------------------
CREATE TABLE clients (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agency_id   uuid NOT NULL REFERENCES agencies(id),
  name        text NOT NULL CHECK (btrim(name) <> ''),
  domain      text CHECK (domain IS NULL OR domain ~ '^[a-z0-9.-]+\.[a-z]{2,}$'),
  cms         text NOT NULL DEFAULT 'other' CHECK (cms IN ('wordpress','webflow','other')),
  archived_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (agency_id, id)
);
CREATE INDEX clients_agency ON clients (agency_id);
CREATE TRIGGER clients_audit AFTER INSERT OR UPDATE OR DELETE ON clients
  FOR EACH ROW EXECUTE FUNCTION audit_row_change('id', 'agency_id');

-- ---------------------------------------------------------------------------
-- People and memberships
-- ---------------------------------------------------------------------------
CREATE TABLE people (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email       text NOT NULL UNIQUE CHECK (email = lower(email) AND email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  full_name   text NOT NULL CHECK (btrim(full_name) <> ''),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER people_audit AFTER INSERT OR UPDATE OR DELETE ON people
  FOR EACH ROW EXECUTE FUNCTION audit_row_change('id');

-- A person's place in one agency. client_id null = agency staff; set = that client's own team.
CREATE TABLE memberships (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agency_id   uuid NOT NULL REFERENCES agencies(id),
  person_id   uuid NOT NULL REFERENCES people(id),
  client_id   uuid,
  title       text NOT NULL CHECK (btrim(title) <> ''),     -- shown in the UI, e.g. "Media buyer"
  is_owner    boolean NOT NULL DEFAULT false,
  active      boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (agency_id, client_id) REFERENCES clients (agency_id, id),
  UNIQUE (agency_id, person_id),
  CONSTRAINT owners_are_agency_level CHECK (NOT is_owner OR client_id IS NULL)
);
CREATE INDEX memberships_person ON memberships (person_id);
CREATE TRIGGER memberships_audit AFTER INSERT OR UPDATE OR DELETE ON memberships
  FOR EACH ROW EXECUTE FUNCTION audit_row_change('id', 'agency_id');

-- An active agency must keep at least one active owner. Checked at commit, so an
-- ownership handover inside one transaction works.
CREATE FUNCTION keep_an_owner() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_agency uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.agency_id ELSE NEW.agency_id END;
BEGIN
  IF EXISTS (SELECT 1 FROM agencies a WHERE a.id = v_agency AND a.status = 'active')
     AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.agency_id = v_agency AND m.is_owner AND m.active) THEN
    RAISE EXCEPTION 'An agency must keep at least one active owner' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER memberships_keep_owner AFTER INSERT OR UPDATE OR DELETE ON memberships
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION keep_an_owner();

-- ---------------------------------------------------------------------------
-- Access levels per area
-- ---------------------------------------------------------------------------
CREATE TABLE modules (
  code         text PRIMARY KEY,
  label        text NOT NULL,
  agency_only  boolean NOT NULL DEFAULT false   -- client-level people can never get more than 'none'
);
INSERT INTO modules (code, label, agency_only) VALUES
  ('seo',      'SEO',                 false),
  ('site',     'Site health and fixes', false),
  ('ads',      'Paid media',          false),
  ('social',   'Social',              false),
  ('reports',  'Reports',             false),
  ('accounts', 'Connected accounts',  false),
  ('margins',  'Retainers and margins', true),
  ('team',     'Team and roles',      true),
  ('branding', 'White-label branding', true);

CREATE TABLE access_levels (level text PRIMARY KEY, rank smallint NOT NULL UNIQUE);
INSERT INTO access_levels VALUES ('none', 0), ('view', 1), ('edit', 2), ('approve', 3);

CREATE TABLE membership_access (
  membership_id uuid NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
  agency_id     uuid NOT NULL REFERENCES agencies(id),
  module        text NOT NULL REFERENCES modules(code),
  level         text NOT NULL REFERENCES access_levels(level),
  PRIMARY KEY (membership_id, module)
);
CREATE TRIGGER membership_access_audit AFTER INSERT OR UPDATE OR DELETE ON membership_access
  FOR EACH ROW EXECUTE FUNCTION audit_row_change('membership_id', 'agency_id');

CREATE FUNCTION membership_access_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE m memberships;
BEGIN
  SELECT * INTO m FROM memberships WHERE id = NEW.membership_id;
  IF m.agency_id <> NEW.agency_id THEN
    RAISE EXCEPTION 'Access row agency does not match the membership' USING ERRCODE = 'check_violation';
  END IF;
  IF m.is_owner THEN
    RAISE EXCEPTION 'Owners always have full access; their access is not set per area' USING ERRCODE = 'check_violation';
  END IF;
  IF m.client_id IS NOT NULL AND NEW.level <> 'none'
     AND (SELECT agency_only FROM modules WHERE code = NEW.module) THEN
    RAISE EXCEPTION 'Client-level people cannot have access to %', NEW.module USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER membership_access_guard BEFORE INSERT OR UPDATE ON membership_access
  FOR EACH ROW EXECUTE FUNCTION membership_access_guard();

-- Making someone an owner or moving them to a client re-checks their saved access.
CREATE FUNCTION membership_scope_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NEW.is_owner AND EXISTS (SELECT 1 FROM membership_access WHERE membership_id = NEW.id) THEN
    DELETE FROM membership_access WHERE membership_id = NEW.id;
  END IF;
  IF NEW.client_id IS NOT NULL AND EXISTS (
       SELECT 1 FROM membership_access a JOIN modules mo ON mo.code = a.module
       WHERE a.membership_id = NEW.id AND mo.agency_only AND a.level <> 'none') THEN
    RAISE EXCEPTION 'Remove agency-only access before moving this person to a client' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER memberships_scope_guard AFTER UPDATE OF is_owner, client_id ON memberships
  FOR EACH ROW EXECUTE FUNCTION membership_scope_guard();

-- The effective level for a membership and area: owners get 'approve' everywhere;
-- inactive memberships and suspended agencies get 'none'.
CREATE FUNCTION access_level(p_membership uuid, p_module text) RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT CASE
    WHEN m.id IS NULL OR NOT m.active OR a.status <> 'active' THEN 'none'
    WHEN m.is_owner THEN 'approve'
    ELSE coalesce((SELECT level FROM membership_access WHERE membership_id = m.id AND module = p_module), 'none')
  END
  FROM (SELECT 1) one
  LEFT JOIN memberships m ON m.id = p_membership
  LEFT JOIN agencies a ON a.id = m.agency_id;
$$;

CREATE FUNCTION has_access(p_membership uuid, p_module text, p_needed text) RETURNS boolean
  LANGUAGE sql STABLE AS $$
  SELECT (SELECT rank FROM access_levels WHERE level = access_level(p_membership, p_module))
      >= (SELECT rank FROM access_levels WHERE level = p_needed);
$$;

-- ---------------------------------------------------------------------------
-- Row-level security for requests made on behalf of a signed-in member.
-- The app sets app.membership_id for the transaction, then SET LOCAL ROLE ordix_member.
-- ---------------------------------------------------------------------------
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ordix_member') THEN CREATE ROLE ordix_member NOLOGIN; END IF;
END $$;

CREATE FUNCTION current_membership() RETURNS memberships
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT m.* FROM memberships m JOIN agencies a ON a.id = m.agency_id
  WHERE m.id = nullif(current_setting('app.membership_id', true), '')::uuid AND m.active AND a.status = 'active';
$$;
CREATE FUNCTION current_agency_id() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT (current_membership()).agency_id $$;
CREATE FUNCTION current_client_id() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT (current_membership()).client_id $$;
CREATE FUNCTION current_can(p_module text, p_needed text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT coalesce(has_access((current_membership()).id, p_module, p_needed), false) $$;

GRANT USAGE ON SCHEMA public TO ordix_member;
GRANT SELECT ON modules, access_levels TO ordix_member;
GRANT SELECT ON agencies, clients, people, memberships, membership_access TO ordix_member;
GRANT UPDATE (name, brand_color, portal_domain, email_sender) ON agencies TO ordix_member;
GRANT INSERT, UPDATE (name, domain, cms, archived_at) ON clients TO ordix_member;
GRANT INSERT ON people TO ordix_member;
GRANT INSERT, UPDATE (title, active, client_id) ON memberships TO ordix_member;
GRANT INSERT, UPDATE, DELETE ON membership_access TO ordix_member;
GRANT EXECUTE ON FUNCTION access_level(uuid, text), has_access(uuid, text, text), current_membership(),
  current_agency_id(), current_client_id(), current_can(text, text) TO ordix_member;

ALTER TABLE agencies ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE membership_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE people ENABLE ROW LEVEL SECURITY;

-- Agencies: see your own; only branding access may change branding.
CREATE POLICY agency_read ON agencies FOR SELECT TO ordix_member USING (id = current_agency_id());
CREATE POLICY agency_brand ON agencies FOR UPDATE TO ordix_member
  USING (id = current_agency_id() AND current_can('branding', 'edit'))
  WITH CHECK (id = current_agency_id());

-- Clients: agency staff see all their agency's clients; client-level people only their own.
CREATE POLICY client_read ON clients FOR SELECT TO ordix_member
  USING (agency_id = current_agency_id() AND (current_client_id() IS NULL OR id = current_client_id()));
CREATE POLICY client_write ON clients FOR INSERT TO ordix_member
  WITH CHECK (agency_id = current_agency_id() AND current_client_id() IS NULL AND current_can('team', 'edit'));
CREATE POLICY client_update ON clients FOR UPDATE TO ordix_member
  USING (agency_id = current_agency_id() AND current_client_id() IS NULL AND current_can('team', 'edit'))
  WITH CHECK (agency_id = current_agency_id());

-- Memberships: agency staff with team access see and manage the agency's people;
-- everyone else sees only themselves (client admins manage their client's people in a later step).
CREATE POLICY membership_read ON memberships FOR SELECT TO ordix_member
  USING (agency_id = current_agency_id()
         AND (id = (current_membership()).id OR (current_client_id() IS NULL AND current_can('team', 'view'))));
CREATE POLICY membership_write ON memberships FOR INSERT TO ordix_member
  WITH CHECK (agency_id = current_agency_id() AND current_client_id() IS NULL AND current_can('team', 'edit') AND NOT is_owner);
CREATE POLICY membership_update ON memberships FOR UPDATE TO ordix_member
  USING (agency_id = current_agency_id() AND current_client_id() IS NULL AND current_can('team', 'edit'))
  WITH CHECK (agency_id = current_agency_id());

CREATE POLICY access_read ON membership_access FOR SELECT TO ordix_member
  USING (agency_id = current_agency_id()
         AND (membership_id = (current_membership()).id OR (current_client_id() IS NULL AND current_can('team', 'view'))));
CREATE POLICY access_write ON membership_access FOR ALL TO ordix_member
  USING (agency_id = current_agency_id() AND current_client_id() IS NULL AND current_can('team', 'edit'))
  WITH CHECK (agency_id = current_agency_id() AND current_client_id() IS NULL AND current_can('team', 'edit'));

-- People: visible when they share your agency (and you could see their membership).
CREATE POLICY people_read ON people FOR SELECT TO ordix_member
  USING (EXISTS (SELECT 1 FROM memberships m WHERE m.person_id = people.id));
CREATE POLICY people_add ON people FOR INSERT TO ordix_member
  WITH CHECK (current_client_id() IS NULL AND current_can('team', 'edit'));

-- The audit log is written by triggers (security definer); members can read their agency's entries
-- when they have team access.
GRANT SELECT ON audit_log TO ordix_member;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON audit_log FOR SELECT TO ordix_member
  USING (agency_id = current_agency_id() AND current_client_id() IS NULL AND current_can('team', 'view'));

-- ---------------------------------------------------------------------------
-- Adding a person (agency staff with team edit access only). A person who already has an
-- Ordix login elsewhere is reused by email; nothing about their other agencies is revealed.
-- ---------------------------------------------------------------------------
CREATE FUNCTION add_member(p_email text, p_full_name text, p_title text, p_client uuid, p_access jsonb)
  RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  me memberships := current_membership();
  v_person uuid;
  v_member uuid;
  k text;
BEGIN
  IF me.id IS NULL OR me.client_id IS NOT NULL OR NOT has_access(me.id, 'team', 'edit') THEN
    RAISE EXCEPTION 'You need edit access to Team and roles to add people' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_client IS NOT NULL AND NOT EXISTS (SELECT 1 FROM clients WHERE id = p_client AND agency_id = me.agency_id) THEN
    RAISE EXCEPTION 'That client is not in your agency' USING ERRCODE = 'insufficient_privilege';
  END IF;
  INSERT INTO people (email, full_name) VALUES (lower(btrim(p_email)), btrim(p_full_name))
    ON CONFLICT (email) DO NOTHING;
  SELECT id INTO v_person FROM people WHERE email = lower(btrim(p_email));
  INSERT INTO memberships (agency_id, person_id, client_id, title) VALUES (me.agency_id, v_person, p_client, p_title)
    RETURNING id INTO v_member;
  FOR k IN SELECT jsonb_object_keys(coalesce(p_access, '{}'::jsonb)) LOOP
    INSERT INTO membership_access (membership_id, agency_id, module, level)
      VALUES (v_member, me.agency_id, k, p_access ->> k);
  END LOOP;
  RETURN v_member;
END $$;
GRANT EXECUTE ON FUNCTION add_member(text, text, text, uuid, jsonb) TO ordix_member;

-- What a member can do, area by area (for the app's menus and buttons).
CREATE VIEW v_my_access AS
  SELECT mo.code AS module, mo.label, access_level((current_membership()).id, mo.code) AS level
  FROM modules mo;
GRANT SELECT ON v_my_access TO ordix_member;
