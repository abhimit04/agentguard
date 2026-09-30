-- AgentGuard relational persistence foundation (schema v12).
-- IDs intentionally remain text so current four-digit agent IDs and UUID records
-- can coexist while data is migrated from agentguard_records.

CREATE TABLE IF NOT EXISTS ag_workspaces (
  id text PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ag_memberships (
  id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  email text NOT NULL,
  display_name text,
  subject text,
  role text NOT NULL CHECK (role IN ('owner','admin','reviewer','operator','viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, email)
);

CREATE TABLE IF NOT EXISTS ag_companies (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  name text NOT NULL,
  gateway_credential_hash text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS ag_agents (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  company_id text NOT NULL,
  name text NOT NULL,
  team text,
  status text NOT NULL DEFAULT 'registered',
  runtime_status text,
  parent_id text,
  credential_hash text,
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id),
  FOREIGN KEY (workspace_id, company_id) REFERENCES ag_companies(workspace_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS ag_policies (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  agent_id text NOT NULL,
  name text NOT NULL,
  effect text NOT NULL CHECK (effect IN ('allow','require_approval','block')),
  enabled boolean NOT NULL DEFAULT true,
  version integer NOT NULL DEFAULT 1,
  priority integer NOT NULL DEFAULT 100,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS ag_approvals (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  agent_id text NOT NULL,
  policy_id text,
  status text NOT NULL CHECK (status IN ('pending','approved','denied')),
  action text NOT NULL,
  action_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id)
);

-- Durable execution ledger. The unique action identity makes policy checks,
-- approval resumes and delivery retries idempotent across process restarts.
CREATE TABLE IF NOT EXISTS ag_governed_actions (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  agent_id text NOT NULL,
  action_ref text NOT NULL,
  action_type text NOT NULL,
  action text NOT NULL,
  resource text NOT NULL DEFAULT '*',
  policy_id text,
  policy_version integer,
  approval_id text,
  state text NOT NULL CHECK (state IN ('awaiting_approval','approved','denied','expired','claimed','completed','failed')),
  execution_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  claimed_at timestamptz,
  completed_at timestamptz,
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, agent_id, action_ref)
);

CREATE UNIQUE INDEX IF NOT EXISTS ag_governed_actions_execution_idx
  ON ag_governed_actions(workspace_id, execution_id) WHERE execution_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ag_assessments (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  agent_id text NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  owner text,
  review_due_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS ag_incidents (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  agent_id text,
  status text NOT NULL CHECK (status IN ('open','investigating','resolved')),
  severity text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  title text NOT NULL,
  owner text,
  source_event_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS ag_alerts (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  incident_id text,
  agent_id text,
  status text NOT NULL CHECK (status IN ('open','acknowledged')),
  severity text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  title text NOT NULL,
  acknowledged_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  acknowledged_at timestamptz,
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS ag_alert_deliveries (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  alert_id text NOT NULL,
  channel text NOT NULL CHECK (channel IN ('webhook')),
  status text NOT NULL CHECK (status IN ('delivered','failed')),
  attempted_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  http_status integer,
  error_message text,
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS ag_audit_events (
  chain_sequence bigserial UNIQUE,
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  agent_id text,
  kind text NOT NULL,
  event_type text,
  actor text NOT NULL,
  message text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  previous_hash text,
  event_hash text,
  payload jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, id)
);

ALTER TABLE ag_audit_events ADD COLUMN IF NOT EXISTS chain_sequence bigserial;

-- Existing installations created hashes in created_at/id order before an
-- explicit sequence existed. Reindex once when the physical backfill did not
-- place a chain root first, preserving the established hash order.
DO $$
DECLARE
  first_previous text;
  offset_value bigint;
BEGIN
  SELECT previous_hash INTO first_previous
  FROM ag_audit_events ORDER BY chain_sequence ASC LIMIT 1;
  IF first_previous IS NOT NULL THEN
    SELECT COALESCE(max(chain_sequence), 0) + count(*) + 1 INTO offset_value FROM ag_audit_events;
    UPDATE ag_audit_events SET chain_sequence = chain_sequence + offset_value;
    WITH ordered AS (
      SELECT workspace_id, id, row_number() OVER (ORDER BY workspace_id, created_at, id) AS sequence_value
      FROM ag_audit_events
    )
    UPDATE ag_audit_events event
    SET chain_sequence = ordered.sequence_value
    FROM ordered
    WHERE event.workspace_id = ordered.workspace_id AND event.id = ordered.id;
    PERFORM setval(pg_get_serial_sequence('ag_audit_events', 'chain_sequence'), COALESCE((SELECT max(chain_sequence) FROM ag_audit_events), 1), true);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS ag_memberships_workspace_idx ON ag_memberships(workspace_id, role);
CREATE INDEX IF NOT EXISTS ag_agents_workspace_status_idx ON ag_agents(workspace_id, status);
CREATE INDEX IF NOT EXISTS ag_approvals_workspace_status_idx ON ag_approvals(workspace_id, status);
CREATE INDEX IF NOT EXISTS ag_incidents_workspace_status_idx ON ag_incidents(workspace_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS ag_alerts_workspace_status_idx ON ag_alerts(workspace_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS ag_alert_deliveries_alert_idx ON ag_alert_deliveries(workspace_id, alert_id, attempted_at DESC);
CREATE INDEX IF NOT EXISTS ag_audit_events_workspace_created_idx ON ag_audit_events(workspace_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ag_audit_events_chain_sequence_idx ON ag_audit_events(chain_sequence);
