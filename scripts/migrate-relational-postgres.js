const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@127.0.0.1:${process.env.POSTGRES_PORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}`;
const pool = new Pool({ connectionString });
const sql = fs.readFileSync(path.join(__dirname, '..', 'infra', 'postgres', '002-relational.sql'), 'utf8');
const statements = [
  ['ag_workspaces', `INSERT INTO ag_workspaces (id,name,created_at,updated_at) SELECT record_id,payload->>'name',COALESCE((payload->>'createdAt')::timestamptz,now()),now() FROM agentguard_records WHERE collection='workspaces' ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,updated_at=now()`],
  ['ag_memberships', `INSERT INTO ag_memberships (id,workspace_id,email,display_name,subject,role,created_at,updated_at) SELECT record_id,workspace_id,payload->>'email',payload->>'name',payload->>'subject',payload->>'role',COALESCE((payload->>'createdAt')::timestamptz,now()),now() FROM agentguard_records WHERE collection='memberships' ON CONFLICT (workspace_id,email) DO UPDATE SET role=EXCLUDED.role,display_name=EXCLUDED.display_name,updated_at=now()`],
  ['ag_companies', `INSERT INTO ag_companies (workspace_id,id,name,gateway_credential_hash,created_at,updated_at,payload) SELECT workspace_id,record_id,payload->>'name',payload->>'gatewayCredentialHash',COALESCE((payload->>'createdAt')::timestamptz,now()),now(),payload FROM agentguard_records WHERE collection='companies' ON CONFLICT (workspace_id,id) DO UPDATE SET name=EXCLUDED.name,gateway_credential_hash=EXCLUDED.gateway_credential_hash,updated_at=now(),payload=EXCLUDED.payload`],
  ['ag_agents', `INSERT INTO ag_agents (workspace_id,id,company_id,name,team,status,runtime_status,parent_id,credential_hash,last_seen_at,created_at,updated_at,payload) SELECT workspace_id,record_id,COALESCE(payload->>'companyId','default'),payload->>'name',payload->>'team',COALESCE(payload->>'status','registered'),payload->>'runtimeStatus',payload->>'parentId',payload->>'credentialHash',NULLIF(payload->>'lastSeenAt','')::timestamptz,COALESCE((payload->>'createdAt')::timestamptz,now()),now(),payload FROM agentguard_records WHERE collection='agents' ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,runtime_status=EXCLUDED.runtime_status,last_seen_at=EXCLUDED.last_seen_at,updated_at=now(),payload=EXCLUDED.payload`],
  ['ag_policies', `INSERT INTO ag_policies (workspace_id,id,agent_id,name,effect,enabled,version,priority,created_at,updated_at,payload) SELECT workspace_id,record_id,payload->>'agentId',payload->>'name',payload->>'effect',COALESCE((payload->>'enabled')::boolean,true),COALESCE((payload->>'version')::integer,1),COALESCE((payload->>'priority')::integer,100),COALESCE((payload->>'createdAt')::timestamptz,now()),now(),payload FROM agentguard_records WHERE collection='policies' ON CONFLICT (workspace_id,id) DO UPDATE SET enabled=EXCLUDED.enabled,version=EXCLUDED.version,priority=EXCLUDED.priority,updated_at=now(),payload=EXCLUDED.payload`],
  ['ag_approvals', `INSERT INTO ag_approvals (workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload) SELECT workspace_id,record_id,payload->>'agentId',payload->>'policyId',COALESCE(payload->>'status','pending'),payload->>'action',payload->>'actionRef',COALESCE((payload->>'createdAt')::timestamptz,now()),NULLIF(payload->>'decidedAt','')::timestamptz,payload FROM agentguard_records WHERE collection='approvals' ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,decided_at=EXCLUDED.decided_at,payload=EXCLUDED.payload`],
  ['ag_assessments', `INSERT INTO ag_assessments (workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload) SELECT workspace_id,record_id,payload->>'agentId',COALESCE(payload->>'status','draft'),payload->>'owner',NULLIF(payload->>'reviewDueAt','')::timestamptz,COALESCE((payload->>'createdAt')::timestamptz,now()),COALESCE((payload->>'updatedAt')::timestamptz,now()),payload FROM agentguard_records WHERE collection='assessments' ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,owner=EXCLUDED.owner,review_due_at=EXCLUDED.review_due_at,updated_at=EXCLUDED.updated_at,payload=EXCLUDED.payload`],
  ['ag_audit_events', `INSERT INTO ag_audit_events (workspace_id,id,agent_id,kind,event_type,actor,message,created_at,payload) SELECT workspace_id,record_id,payload->>'agentId',COALESCE(payload->>'kind','action'),payload->>'eventType',COALESCE(payload->>'actor','system'),COALESCE(payload->>'message','AgentGuard event'),COALESCE((payload->>'createdAt')::timestamptz,now()),payload FROM agentguard_records WHERE collection='events' ON CONFLICT (workspace_id,id) DO NOTHING`]
];

async function main() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(sql);
    const result = {};
    for (const [name, statement] of statements) result[name] = (await client.query(statement)).rowCount;
    await client.query('COMMIT');
    console.log(JSON.stringify({ migrated: result }));
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); await pool.end(); }
}

main().catch(error => { console.error(error.message); process.exit(1); });
