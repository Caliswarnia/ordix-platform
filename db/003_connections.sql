-- Connected accounts: a client's Google (Search Console, Analytics) and later Meta, linked through OAuth.
--
-- Rules the database enforces:
--   - only people with 'accounts' edit access connect or disconnect, and only for clients they can see
--     (so a client admin can connect their own company's accounts; agency staff need the access too)
--   - tokens never live here: the secret store holds them; a connection keeps only a reference
--   - an OAuth state is single-use, tied to the member who started it, and expires after 10 minutes
--   - disconnecting clears the token reference at once and deletes the properties synced from it;
--     the app deletes the token from the secret store and revokes it with the provider
--   - one selected Search Console site and one selected Analytics property per client
--   - agencies may bring their own OAuth app (client id + secret in the secret store); members never
--     see the secret reference
--   - members never read token or secret references; every change is audited

CREATE TABLE oauth_apps (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agency_id   uuid NOT NULL REFERENCES agencies(id),
  provider    text NOT NULL CHECK (provider IN ('google','meta')),
  app_client_id text NOT NULL CHECK (btrim(app_client_id) <> ''),
  secret_ref  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (agency_id, provider)
);
CREATE TRIGGER oauth_apps_audit AFTER INSERT OR UPDATE OR DELETE ON oauth_apps
  FOR EACH ROW EXECUTE FUNCTION audit_row_change('id', 'agency_id');

CREATE TABLE connections (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agency_id        uuid NOT NULL REFERENCES agencies(id),
  client_id        uuid NOT NULL,
  provider         text NOT NULL CHECK (provider IN ('google','meta')),
  account_email    text,
  scopes           text[] NOT NULL DEFAULT '{}',
  token_ref        text,
  via_agency_app   boolean NOT NULL DEFAULT false,
  status           text NOT NULL DEFAULT 'connected' CHECK (status IN ('connected','needs_reconnect','disconnected')),
  connected_by     text NOT NULL,
  connected_at     timestamptz NOT NULL DEFAULT now(),
  disconnected_at  timestamptz,
  disconnected_by  text,
  FOREIGN KEY (agency_id, client_id) REFERENCES clients (agency_id, id),
  CONSTRAINT disconnected_has_no_token CHECK ((status = 'disconnected') = (token_ref IS NULL AND disconnected_at IS NOT NULL))
);
CREATE INDEX connections_client ON connections (client_id) WHERE status <> 'disconnected';
-- Audited without the token reference.
CREATE FUNCTION audit_connection() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO audit_log (actor, agency_id, action, entity, entity_id, before, after)
  VALUES (coalesce(nullif(current_setting('app.actor', true), ''), 'system:unknown'), NEW.agency_id, lower(TG_OP), 'connections', NEW.id::text,
          CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD) - 'token_ref' END, to_jsonb(NEW) - 'token_ref');
  RETURN NEW;
END $$;
CREATE TRIGGER connections_audit AFTER INSERT OR UPDATE ON connections FOR EACH ROW EXECUTE FUNCTION audit_connection();
CREATE TRIGGER connections_no_delete BEFORE DELETE ON connections FOR EACH ROW EXECUTE FUNCTION forbid_change();

-- A disconnected connection stays disconnected (reconnecting creates a new one).
CREATE FUNCTION connection_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'disconnected' THEN
    RAISE EXCEPTION 'A disconnected account stays disconnected; connect it again instead' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.agency_id <> OLD.agency_id OR NEW.client_id <> OLD.client_id OR NEW.provider <> OLD.provider THEN
    RAISE EXCEPTION 'A connection can''t move to another client' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER connections_guard BEFORE UPDATE ON connections FOR EACH ROW EXECUTE FUNCTION connection_guard();

CREATE TABLE connection_properties (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  connection_id  uuid NOT NULL REFERENCES connections(id),
  agency_id      uuid NOT NULL REFERENCES agencies(id),
  client_id      uuid NOT NULL,
  kind           text NOT NULL CHECK (kind IN ('search_console_site','ga4_property','meta_ad_account','meta_page')),
  external_id    text NOT NULL,
  label          text NOT NULL,
  selected       boolean NOT NULL DEFAULT false,
  UNIQUE (connection_id, kind, external_id)
);
CREATE UNIQUE INDEX one_selected_per_kind ON connection_properties (client_id, kind) WHERE selected;
CREATE TRIGGER connection_properties_audit AFTER INSERT OR UPDATE OR DELETE ON connection_properties
  FOR EACH ROW EXECUTE FUNCTION audit_row_change('id', 'agency_id');

CREATE TABLE oauth_states (
  state_sha256   char(64) PRIMARY KEY CHECK (state_sha256 ~ '^[0-9a-f]{64}$'),
  membership_id  uuid NOT NULL REFERENCES memberships(id),
  client_id      uuid NOT NULL REFERENCES clients(id),
  provider       text NOT NULL CHECK (provider IN ('google','meta')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL DEFAULT now() + interval '10 minutes',
  used_at        timestamptz
);

-- ---------------------------------------------------------------------------
-- Access for members
-- ---------------------------------------------------------------------------
CREATE FUNCTION can_reach_client(p_client uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM clients c WHERE c.id = p_client AND c.agency_id = current_agency_id()
                 AND c.archived_at IS NULL AND (current_client_id() IS NULL OR c.id = current_client_id()));
$$;
GRANT EXECUTE ON FUNCTION can_reach_client(uuid) TO ordix_member;

GRANT SELECT (id, agency_id, client_id, provider, account_email, scopes, via_agency_app, status, connected_by, connected_at, disconnected_at, disconnected_by)
  ON connections TO ordix_member;
GRANT SELECT ON connection_properties TO ordix_member;
GRANT SELECT (id, agency_id, provider, app_client_id, created_at) ON oauth_apps TO ordix_member;
ALTER TABLE connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_properties ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_states ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON oauth_states FROM ordix_member;

CREATE POLICY connection_read ON connections FOR SELECT TO ordix_member
  USING (can_reach_client(client_id) AND current_can('accounts', 'view'));
CREATE POLICY property_read ON connection_properties FOR SELECT TO ordix_member
  USING (can_reach_client(client_id));
CREATE POLICY oauth_app_read ON oauth_apps FOR SELECT TO ordix_member
  USING (agency_id = current_agency_id() AND current_client_id() IS NULL AND current_can('team', 'view'));

-- Start connecting: records a single-use state for the signed-in member.
CREATE FUNCTION begin_connection(p_client uuid, p_provider text, p_state_sha256 text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE me memberships := current_membership();
BEGIN
  IF me.id IS NULL OR NOT has_access(me.id, 'accounts', 'edit') THEN
    RAISE EXCEPTION 'You need edit access to Connected accounts' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT can_reach_client(p_client) THEN
    RAISE EXCEPTION 'That client is not available to you' USING ERRCODE = 'insufficient_privilege';
  END IF;
  DELETE FROM oauth_states WHERE expires_at < now() - interval '1 day';
  INSERT INTO oauth_states (state_sha256, membership_id, client_id, provider) VALUES (p_state_sha256, me.id, p_client, p_provider);
END $$;
GRANT EXECUTE ON FUNCTION begin_connection(uuid, text, text) TO ordix_member;

-- Used by the server (not members) when the provider sends the person back. Single use; refuses
-- an expired state, or one whose member lost access in the meantime.
CREATE FUNCTION consume_oauth_state(p_state_sha256 text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE s oauth_states%ROWTYPE;
BEGIN
  UPDATE oauth_states SET used_at = now()
    WHERE state_sha256 = p_state_sha256 AND used_at IS NULL AND expires_at > now() RETURNING * INTO s;
  IF NOT FOUND THEN RAISE EXCEPTION 'This sign-in link has expired or was already used. Start again.'; END IF;
  IF NOT has_access(s.membership_id, 'accounts', 'edit') THEN RAISE EXCEPTION 'You no longer have access to connect accounts'; END IF;
  RETURN jsonb_build_object('membershipId', s.membership_id, 'clientId', s.client_id, 'provider', s.provider,
    'agencyId', (SELECT agency_id FROM memberships WHERE id = s.membership_id),
    'personId', (SELECT person_id FROM memberships WHERE id = s.membership_id));
END $$;

-- Disconnect: returns the token reference so the app can delete and revoke it.
CREATE FUNCTION disconnect_connection(p_connection uuid) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  me memberships := current_membership();
  c  connections%ROWTYPE;
BEGIN
  SELECT * INTO c FROM connections WHERE id = p_connection FOR UPDATE;
  IF NOT FOUND OR NOT can_reach_client(c.client_id) THEN RAISE EXCEPTION 'Connection not found' USING ERRCODE = 'no_data_found'; END IF;
  IF NOT has_access(me.id, 'accounts', 'edit') THEN
    RAISE EXCEPTION 'You need edit access to Connected accounts' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF c.status = 'disconnected' THEN RETURN NULL; END IF;
  DELETE FROM connection_properties WHERE connection_id = c.id;
  UPDATE connections SET status = 'disconnected', token_ref = NULL, disconnected_at = now(),
    disconnected_by = current_setting('app.actor', true) WHERE id = c.id;
  RETURN c.token_ref;
END $$;
GRANT EXECUTE ON FUNCTION disconnect_connection(uuid) TO ordix_member;

-- Choose which site/property feeds a client's dashboards (one of each kind per client).
CREATE FUNCTION select_property(p_property uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE p connection_properties%ROWTYPE;
BEGIN
  SELECT * INTO p FROM connection_properties WHERE id = p_property;
  IF NOT FOUND OR NOT can_reach_client(p.client_id) THEN RAISE EXCEPTION 'Not found' USING ERRCODE = 'no_data_found'; END IF;
  IF NOT current_can('accounts', 'edit') THEN
    RAISE EXCEPTION 'You need edit access to Connected accounts' USING ERRCODE = 'insufficient_privilege';
  END IF;
  UPDATE connection_properties SET selected = false WHERE client_id = p.client_id AND kind = p.kind AND selected AND id <> p.id;
  UPDATE connection_properties SET selected = true WHERE id = p.id;
END $$;
GRANT EXECUTE ON FUNCTION select_property(uuid) TO ordix_member;
