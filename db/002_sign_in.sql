-- Sign-in: password + authenticator code (TOTP), sessions, lockout. Ported from the
-- Health Company Platform's 014_staff_accounts.sql.
--
-- The app checks the password (scrypt) and the code (RFC 6238); the database enforces the rest:
--   - a session starts only for a person with sign-in enabled, not locked, MFA set up,
--     and at least one active membership in an active agency
--   - 5 failed attempts lock sign-in for 15 minutes
--   - sessions end after 30 minutes idle or 12 hours, whichever comes first, and on sign-out
--   - an authenticator code is accepted once (no replay)
--   - every sign-in attempt is kept, append-only
--   - a session works in one agency workspace at a time; switching re-checks the membership,
--     and a membership that is deactivated (or an agency suspended) stops working at once
-- Sign-in state lives apart from `people`, so members who can see a teammate's name and
-- email never see their lock status, password hash or authenticator reference.
-- Authenticator secrets live in the secret store; the database keeps only a reference.

CREATE TABLE person_sign_in (
  person_id            uuid PRIMARY KEY REFERENCES people(id),
  enabled              boolean NOT NULL DEFAULT true,
  password_hash        text NOT NULL CHECK (password_hash ~ '^scrypt\$'),
  password_changed_at  timestamptz NOT NULL DEFAULT now(),
  must_change_password boolean NOT NULL DEFAULT true,
  totp_secret_ref      text,
  mfa_enrolled_at      timestamptz,
  last_totp_step       bigint,
  failed_attempts      integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  locked_until         timestamptz,
  CONSTRAINT mfa_has_secret CHECK (mfa_enrolled_at IS NULL OR totp_secret_ref IS NOT NULL)
);
-- Audited without the password hash.
CREATE FUNCTION audit_sign_in_settings() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_actor text := coalesce(nullif(current_setting('app.actor', true), ''), 'system:unknown');
BEGIN
  IF TG_OP = 'UPDATE' AND (OLD.enabled, OLD.must_change_password, OLD.mfa_enrolled_at, OLD.password_changed_at)
     IS NOT DISTINCT FROM (NEW.enabled, NEW.must_change_password, NEW.mfa_enrolled_at, NEW.password_changed_at) THEN
    RETURN NEW;   -- counters and replay steps change on every sign-in; not worth an audit row
  END IF;
  INSERT INTO audit_log (actor, action, entity, entity_id, before, after)
  VALUES (v_actor, lower(TG_OP), 'person_sign_in', NEW.person_id::text,
    CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD) - 'password_hash' - 'totp_secret_ref' END,
    to_jsonb(NEW) - 'password_hash' - 'totp_secret_ref');
  RETURN NEW;
END $$;
CREATE TRIGGER person_sign_in_audit AFTER INSERT OR UPDATE ON person_sign_in
  FOR EACH ROW EXECUTE FUNCTION audit_sign_in_settings();

CREATE TABLE sessions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  person_id      uuid NOT NULL REFERENCES people(id),
  membership_id  uuid REFERENCES memberships(id),       -- the workspace in use; null until chosen
  token_sha256   char(64) NOT NULL UNIQUE CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at   timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL DEFAULT now() + interval '12 hours',
  ended_at       timestamptz,
  ip             inet,
  user_agent     text
);
CREATE INDEX sessions_person ON sessions (person_id) WHERE ended_at IS NULL;

CREATE TABLE sign_in_events (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  email       text NOT NULL,
  person_id   uuid REFERENCES people(id),
  outcome     text NOT NULL CHECK (outcome IN ('signed_in','bad_password','bad_code','code_reused','locked','unknown_or_disabled',
                                              'no_workspace','mfa_enrolled','password_changed','workspace_chosen','signed_out')),
  membership_id uuid,
  ip          inet,
  user_agent  text
);
CREATE TRIGGER sign_in_events_append_only BEFORE UPDATE OR DELETE ON sign_in_events
  FOR EACH ROW EXECUTE FUNCTION forbid_change();

-- None of these tables are reachable by members directly.
REVOKE ALL ON person_sign_in, sessions, sign_in_events FROM ordix_member;

-- Workspaces a person can work in right now.
CREATE FUNCTION person_workspaces(p_person uuid) RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(jsonb_build_object('membershipId', m.id, 'agency', a.name, 'agencySlug', a.slug,
           'clientId', m.client_id, 'client', c.name, 'title', m.title, 'isOwner', m.is_owner) ORDER BY a.name, c.name), '[]')
  FROM memberships m JOIN agencies a ON a.id = m.agency_id LEFT JOIN clients c ON c.id = m.client_id
  WHERE m.person_id = p_person AND m.active AND a.status = 'active' AND (c.id IS NULL OR c.archived_at IS NULL);
$$;

-- A failed password or code: counted; the 5th locks sign-in for 15 minutes.
CREATE FUNCTION sign_in_failed(p_person uuid, p_outcome text, p_ip text, p_ua text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE s person_sign_in%ROWTYPE;
BEGIN
  UPDATE person_sign_in SET failed_attempts = failed_attempts + 1,
    locked_until = CASE WHEN failed_attempts + 1 >= 5 THEN now() + interval '15 minutes' ELSE locked_until END
  WHERE person_id = p_person RETURNING * INTO s;
  INSERT INTO sign_in_events (email, person_id, outcome, ip, user_agent)
    SELECT email, id, p_outcome, nullif(p_ip, '')::inet, p_ua FROM people WHERE id = p_person;
  IF s.failed_attempts >= 5 THEN UPDATE person_sign_in SET failed_attempts = 0 WHERE person_id = p_person; END IF;
  RETURN jsonb_build_object('locked', coalesce(s.locked_until > now(), false));
END $$;

-- Record a code as used. Refuses a step already used or older (replay).
CREATE FUNCTION use_totp_step(p_person uuid, p_step bigint) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
  UPDATE person_sign_in SET last_totp_step = p_step WHERE person_id = p_person AND (last_totp_step IS NULL OR last_totp_step < p_step);
  RETURN FOUND;
END $$;

-- Start a session after a correct password and code. When the person has exactly one
-- workspace it is chosen automatically.
CREATE FUNCTION start_session(p_person uuid, p_token_sha256 text, p_ip text, p_ua text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  s  person_sign_in%ROWTYPE;
  p  people%ROWTYPE;
  ws jsonb := person_workspaces(p_person);
BEGIN
  SELECT * INTO s FROM person_sign_in WHERE person_id = p_person;
  SELECT * INTO p FROM people WHERE id = p_person;
  IF NOT FOUND OR s.person_id IS NULL OR NOT s.enabled THEN RAISE EXCEPTION 'Sign-in is turned off for this account'; END IF;
  IF s.locked_until > now() THEN RAISE EXCEPTION 'Sign-in is locked until %', to_char(s.locked_until, 'HH24:MI'); END IF;
  IF s.mfa_enrolled_at IS NULL THEN RAISE EXCEPTION 'Set up two-step sign-in first'; END IF;
  IF jsonb_array_length(ws) = 0 THEN
    INSERT INTO sign_in_events (email, person_id, outcome, ip, user_agent) VALUES (p.email, p.id, 'no_workspace', nullif(p_ip, '')::inet, p_ua);
    RAISE EXCEPTION 'Your account is not part of an active agency';
  END IF;
  UPDATE person_sign_in SET failed_attempts = 0, locked_until = NULL WHERE person_id = p_person;
  INSERT INTO sessions (person_id, token_sha256, ip, user_agent, membership_id)
    VALUES (p.id, p_token_sha256, nullif(p_ip, '')::inet, p_ua,
            CASE WHEN jsonb_array_length(ws) = 1 THEN (ws -> 0 ->> 'membershipId')::uuid END);
  INSERT INTO sign_in_events (email, person_id, outcome, ip, user_agent) VALUES (p.email, p.id, 'signed_in', nullif(p_ip, '')::inet, p_ua);
  RETURN session_for(p_token_sha256);
END $$;

-- The signed-in person for a session token, or null. Ends sessions that are idle 30 minutes,
-- past 12 hours, or whose sign-in was turned off. Drops the chosen workspace if that membership
-- or agency is no longer active.
CREATE FUNCTION session_for(p_token_sha256 text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  ss sessions%ROWTYPE;
  s  person_sign_in%ROWTYPE;
  p  people%ROWTYPE;
  ws jsonb;
  cur jsonb;
BEGIN
  SELECT * INTO ss FROM sessions WHERE token_sha256 = p_token_sha256 AND ended_at IS NULL;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO s FROM person_sign_in WHERE person_id = ss.person_id;
  IF NOT s.enabled OR now() > ss.expires_at OR now() > ss.last_seen_at + interval '30 minutes' THEN
    UPDATE sessions SET ended_at = now() WHERE id = ss.id;
    RETURN NULL;
  END IF;
  SELECT * INTO p FROM people WHERE id = ss.person_id;
  ws := person_workspaces(p.id);
  SELECT w INTO cur FROM jsonb_array_elements(ws) w WHERE (w ->> 'membershipId')::uuid = ss.membership_id;
  UPDATE sessions SET last_seen_at = now(), membership_id = CASE WHEN cur IS NULL THEN NULL ELSE membership_id END WHERE id = ss.id;
  RETURN jsonb_build_object('personId', p.id, 'email', p.email, 'fullName', p.full_name,
    'mustChangePassword', s.must_change_password, 'workspaces', ws, 'workspace', cur);
END $$;

-- Choose (or switch) the workspace for this session. Refuses one that isn't the person's or isn't active.
CREATE FUNCTION choose_workspace(p_token_sha256 text, p_membership uuid) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE ss sessions%ROWTYPE;
BEGIN
  SELECT * INTO ss FROM sessions WHERE token_sha256 = p_token_sha256 AND ended_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'Sign in to continue'; END IF;
  IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(person_workspaces(ss.person_id)) w WHERE (w ->> 'membershipId')::uuid = p_membership) THEN
    RAISE EXCEPTION 'That workspace is not available to you';
  END IF;
  UPDATE sessions SET membership_id = p_membership WHERE id = ss.id;
  INSERT INTO sign_in_events (email, person_id, outcome, membership_id)
    SELECT email, id, 'workspace_chosen', p_membership FROM people WHERE id = ss.person_id;
  RETURN session_for(p_token_sha256);
END $$;

CREATE FUNCTION end_session(p_token_sha256 text) RETURNS void LANGUAGE sql AS $$
  WITH e AS (UPDATE sessions SET ended_at = now() WHERE token_sha256 = p_token_sha256 AND ended_at IS NULL RETURNING person_id)
  INSERT INTO sign_in_events (email, person_id, outcome) SELECT p.email, p.id, 'signed_out' FROM e JOIN people p ON p.id = e.person_id;
$$;

-- Turning sign-in off ends that person's sessions at once.
CREATE FUNCTION end_sessions_when_disabled() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.enabled AND NOT NEW.enabled THEN UPDATE sessions SET ended_at = now() WHERE person_id = NEW.person_id AND ended_at IS NULL; END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER person_sign_in_disable AFTER UPDATE OF enabled ON person_sign_in
  FOR EACH ROW EXECUTE FUNCTION end_sessions_when_disabled();
