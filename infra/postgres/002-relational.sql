-- AgentGuard relational persistence foundation (schema v13).
-- IDs intentionally remain text so current four-digit agent IDs and UUID records
-- can coexist while data is migrated from agentguard_records.

CREATE TABLE IF NOT EXISTS ag_workspaces (
  id text PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Retention is opt-in. No cleanup runs until archive and restore proofs exist.
ALTER TABLE ag_workspaces ADD COLUMN IF NOT EXISTS audit_retention_days integer CHECK (audit_retention_days BETWEEN 30 AND 3650);
ALTER TABLE ag_workspaces ADD COLUMN IF NOT EXISTS retention_updated_by text;
ALTER TABLE ag_workspaces ADD COLUMN IF NOT EXISTS retention_updated_at timestamptz;
ALTER TABLE ag_workspaces ADD COLUMN IF NOT EXISTS retention_version integer NOT NULL DEFAULT 0;

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

CREATE TABLE IF NOT EXISTS ag_assessment_revisions (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  assessment_id text NOT NULL,
  agent_id text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  scoring_model text NOT NULL,
  score integer NOT NULL CHECK (score BETWEEN 0 AND 100),
  reviewer text NOT NULL,
  rationale text,
  created_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL,
  PRIMARY KEY (workspace_id, assessment_id, version)
);

CREATE INDEX IF NOT EXISTS ag_assessment_revisions_agent_idx ON ag_assessment_revisions(workspace_id, agent_id, version DESC);

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

-- Durable webhook work is separate from the append-only per-attempt delivery
-- history above. A lease makes abandoned in-flight work recoverable after a
-- process crash and prevents two workers from claiming the same alert at once.
CREATE TABLE IF NOT EXISTS ag_alert_outbox (
  workspace_id text NOT NULL,
  alert_id text NOT NULL,
  channel text NOT NULL CHECK (channel IN ('webhook')),
  status text NOT NULL CHECK (status IN ('queued','in_flight','delivered','dead')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at timestamptz NOT NULL DEFAULT now(),
  locked_until timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, alert_id, channel),
  FOREIGN KEY (workspace_id, alert_id) REFERENCES ag_alerts(workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ag_alert_outbox_ready_idx ON ag_alert_outbox(status, available_at, locked_until);

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

CREATE TABLE IF NOT EXISTS ag_audit_legal_holds (
  workspace_id text NOT NULL REFERENCES ag_workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  reason text NOT NULL,
  case_reference text,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  released_by text,
  released_at timestamptz,
  release_reason text,
  PRIMARY KEY (workspace_id, id),
  CHECK ((released_at IS NULL AND released_by IS NULL AND release_reason IS NULL) OR
         (released_at IS NOT NULL AND released_by IS NOT NULL AND release_reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ag_audit_legal_holds_active_idx ON ag_audit_legal_holds(workspace_id, created_at DESC) WHERE released_at IS NULL;

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

-- Receipt and agent state commit with the audit event. Heartbeats have receipts
-- for retry safety, but deliberately do not appear in the activity audit log.
CREATE TABLE IF NOT EXISTS ag_telemetry_receipts (
  workspace_id text NOT NULL,
  company_id text NOT NULL,
  agent_id text NOT NULL,
  event_id text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, company_id, agent_id, event_id),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES ag_agents(workspace_id, id)
);

-- Shared fixed-window limiter for telemetry and governed-action ingestion.
-- PostgreSQL makes the decision consistent across application instances.
CREATE TABLE IF NOT EXISTS ag_rate_limit_buckets (
  scope text NOT NULL,
  identity_hash text NOT NULL,
  window_started timestamptz NOT NULL,
  request_count integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, identity_hash, window_started)
);
CREATE INDEX IF NOT EXISTS ag_rate_limit_buckets_expiry_idx ON ag_rate_limit_buckets(window_started);

-- Daily budget reservations are created inside the governed-action transaction.
-- The locked agent row serializes reservations for one agent, preventing a
-- concurrent pair of requests from spending the same remaining allowance.
CREATE TABLE IF NOT EXISTS ag_budget_reservations (
  workspace_id text NOT NULL,
  policy_id text NOT NULL,
  agent_id text NOT NULL,
  action_ref text NOT NULL,
  budget_day date NOT NULL DEFAULT CURRENT_DATE,
  reserved_tokens bigint NOT NULL DEFAULT 0,
  reserved_cost_usd numeric(14,4) NOT NULL DEFAULT 0,
  reserved_actions integer NOT NULL DEFAULT 1,
  released_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, policy_id, agent_id, action_ref, budget_day),
  FOREIGN KEY (workspace_id, policy_id) REFERENCES ag_policies(workspace_id, id),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES ag_agents(workspace_id, id)
);
CREATE INDEX IF NOT EXISTS ag_budget_reservations_daily_idx ON ag_budget_reservations(workspace_id, policy_id, agent_id, budget_day) WHERE released_at IS NULL;
