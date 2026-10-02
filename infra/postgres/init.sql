CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text UNIQUE NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oidc_subject text UNIQUE NOT NULL,
  email text NOT NULL,
  display_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz
);

CREATE TABLE IF NOT EXISTS workspace_memberships (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner','admin','reviewer','operator','viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS agents (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  id text NOT NULL,
  name text NOT NULL,
  team text NOT NULL,
  tools jsonb NOT NULL DEFAULT '[]',
  status text NOT NULL DEFAULT 'registered' CHECK (status IN ('registered','healthy','offline','archived')),
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  agent_id text NOT NULL,
  name text NOT NULL,
  scope text NOT NULL,
  action_type text NOT NULL,
  resource_pattern text NOT NULL DEFAULT '*',
  effect text NOT NULL CHECK (effect IN ('allow','require_approval','block')),
  priority integer NOT NULL DEFAULT 100,
  enabled boolean NOT NULL DEFAULT true,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  agent_id text NOT NULL,
  action text NOT NULL,
  resource text,
  action_ref text,
  policy_id uuid REFERENCES policies(id),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied')),
  decided_by uuid REFERENCES users(id),
  rationale text,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz
);

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  agent_id text,
  actor text NOT NULL,
  kind text NOT NULL,
  message text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_events_workspace_created_idx ON audit_events(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS approvals_workspace_status_idx ON approvals(workspace_id, status);
CREATE INDEX IF NOT EXISTS agents_workspace_status_idx ON agents(workspace_id, status);

-- Runtime persistence used by the Node application. Each domain record is stored
-- separately and carries an explicit workspace boundary. The legacy
-- agentguard_store JSON document is read once by storage.js only for migration.
CREATE TABLE IF NOT EXISTS agentguard_metadata (
  id integer PRIMARY KEY CHECK (id = 1),
  schema_version integer NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agentguard_records (
  collection text NOT NULL CHECK (collection IN ('workspaces','memberships','companies','agents','policies','approvals','assessments','events')),
  workspace_id text NOT NULL,
  record_id text NOT NULL,
  payload jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (collection, workspace_id, record_id)
);

CREATE INDEX IF NOT EXISTS agentguard_records_workspace_collection_idx
  ON agentguard_records(workspace_id, collection);
