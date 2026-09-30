const { postgresQuery, usePostgres } = require('../storage');

function payload(row) {
  if (!row) return null;
  return { ...row.payload, workspaceId: row.workspace_id, id: row.id, companyId: row.company_id, name: row.name, team: row.team, status: row.status, runtimeStatus: row.runtime_status, parentId: row.parent_id, lastSeenAt: row.last_seen_at?.toISOString?.() || row.last_seen_at || null };
}

async function list(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT workspace_id,id,company_id,name,team,status,runtime_status,parent_id,last_seen_at,payload FROM ag_agents WHERE workspace_id=$1 ORDER BY name,id', [workspaceId]);
  return result.rows.map(payload);
}

async function listCompanies(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT workspace_id,id,name,payload FROM ag_companies WHERE workspace_id=$1 ORDER BY name,id', [workspaceId]);
  return result.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, name: row.name }));
}

async function upsertCompany(company) {
  if (!usePostgres) return undefined;
  await postgresQuery(`INSERT INTO ag_companies (workspace_id,id,name,gateway_credential_hash,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,COALESCE($5::timestamptz,now()),now(),$6::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET name=EXCLUDED.name,gateway_credential_hash=EXCLUDED.gateway_credential_hash,updated_at=now(),payload=EXCLUDED.payload`, [company.workspaceId || 'default', company.id, company.name, company.gatewayCredentialHash || null, company.createdAt || null, JSON.stringify(company)]);
}

async function upsert(agent) {
  if (!usePostgres) return undefined;
  await postgresQuery(`INSERT INTO ag_agents (workspace_id,id,company_id,name,team,status,runtime_status,parent_id,credential_hash,last_seen_at,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,'')::timestamptz,COALESCE($11::timestamptz,now()),now(),$12::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET company_id=EXCLUDED.company_id,name=EXCLUDED.name,team=EXCLUDED.team,status=EXCLUDED.status,runtime_status=EXCLUDED.runtime_status,parent_id=EXCLUDED.parent_id,credential_hash=EXCLUDED.credential_hash,last_seen_at=EXCLUDED.last_seen_at,updated_at=now(),payload=EXCLUDED.payload`, [agent.workspaceId || 'default', agent.id, agent.companyId || 'default', agent.name, agent.team || null, agent.status || 'registered', agent.runtimeStatus || null, agent.parentId || null, agent.credentialHash || null, agent.lastSeenAt || '', agent.createdAt || null, JSON.stringify(agent)]);
}

module.exports = { list, listCompanies, upsert, upsertCompany };
