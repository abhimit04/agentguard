const { postgresQuery, postgresTransaction, usePostgres } = require('../storage');
const { appendEventWithClient } = require('./governance');

function payload(row) {
  if (!row) return null;
  return { ...row.payload, workspaceId: row.workspace_id, id: row.id, companyId: row.company_id, name: row.name, team: row.team, status: row.status, runtimeStatus: row.runtime_status, parentId: row.parent_id, lastSeenAt: row.last_seen_at?.toISOString?.() || row.last_seen_at || null, updatedAt: row.updated_at?.toISOString?.() || row.updated_at || row.payload.updatedAt || null };
}

async function get(workspaceId, agentId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT workspace_id,id,company_id,name,team,status,runtime_status,parent_id,last_seen_at,updated_at,payload FROM ag_agents WHERE workspace_id=$1 AND id=$2', [workspaceId, agentId]);
  return payload(result.rows[0]);
}

async function list(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT workspace_id,id,company_id,name,team,status,runtime_status,parent_id,last_seen_at,payload FROM ag_agents WHERE workspace_id=$1 ORDER BY name,id', [workspaceId]);
  return result.rows.map(payload);
}

async function listCompanies(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT workspace_id,id,name,updated_at,payload FROM ag_companies WHERE workspace_id=$1 ORDER BY name,id', [workspaceId]);
  return result.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, name: row.name, updatedAt: row.updated_at?.toISOString?.() || row.updated_at || row.payload.updatedAt || null }));
}

async function getCompany(workspaceId, companyId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT workspace_id,id,name,updated_at,payload FROM ag_companies WHERE workspace_id=$1 AND id=$2', [workspaceId, companyId]);
  const row = result.rows[0];
  return row ? { ...row.payload, workspaceId: row.workspace_id, id: row.id, name: row.name, updatedAt: row.updated_at?.toISOString?.() || row.updated_at || row.payload.updatedAt || null } : null;
}

async function upsertCompany(company) {
  if (!usePostgres) return undefined;
  await postgresQuery(`INSERT INTO ag_companies (workspace_id,id,name,gateway_credential_hash,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,COALESCE($5::timestamptz,now()),now(),$6::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET name=EXCLUDED.name,gateway_credential_hash=EXCLUDED.gateway_credential_hash,updated_at=now(),payload=EXCLUDED.payload`, [company.workspaceId || 'default', company.id, company.name, company.gatewayCredentialHash || null, company.createdAt || null, JSON.stringify(company)]);
}

async function saveCompanyWithAudit(company, audit, { create = false, expectedUpdatedAt = null } = {}) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const workspaceId = company.workspaceId || 'default';
    const current = await client.query('SELECT updated_at FROM ag_companies WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [workspaceId, company.id]);
    if (create && current.rowCount) { const error = new Error('Company ID already exists in this workspace'); error.statusCode = 409; throw error; }
    if (!create && !current.rowCount) { const error = new Error('Company not found'); error.statusCode = 404; throw error; }
    if (!create && expectedUpdatedAt && new Date(current.rows[0].updated_at).getTime() !== new Date(expectedUpdatedAt).getTime()) { const error = new Error('Company changed since it was loaded. Refresh and retry.'); error.statusCode = 409; throw error; }
    const updatedAt = company.updatedAt || new Date().toISOString();
    if (create) {
      await client.query(`INSERT INTO ag_companies (workspace_id,id,name,gateway_credential_hash,created_at,updated_at,payload)
        VALUES ($1,$2,$3,$4,COALESCE($5::timestamptz,now()),$6::timestamptz,$7::jsonb)`,
      [workspaceId, company.id, company.name, company.gatewayCredentialHash || null, company.createdAt || null, updatedAt, JSON.stringify({ ...company, updatedAt })]);
    } else {
      await client.query('UPDATE ag_companies SET name=$3,gateway_credential_hash=$4,updated_at=$5::timestamptz,payload=$6::jsonb WHERE workspace_id=$1 AND id=$2',
        [workspaceId, company.id, company.name, company.gatewayCredentialHash || null, updatedAt, JSON.stringify({ ...company, updatedAt })]);
    }
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Audit event ID already exists; company change was not committed'); error.statusCode = 409; throw error; }
    return { company: { ...company, updatedAt }, audit: savedAudit };
  });
}

async function upsert(agent) {
  if (!usePostgres) return undefined;
  await postgresQuery(`INSERT INTO ag_agents (workspace_id,id,company_id,name,team,status,runtime_status,parent_id,credential_hash,last_seen_at,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,'')::timestamptz,COALESCE($11::timestamptz,now()),now(),$12::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET company_id=EXCLUDED.company_id,name=EXCLUDED.name,team=EXCLUDED.team,status=EXCLUDED.status,runtime_status=EXCLUDED.runtime_status,parent_id=EXCLUDED.parent_id,credential_hash=EXCLUDED.credential_hash,last_seen_at=EXCLUDED.last_seen_at,updated_at=now(),payload=EXCLUDED.payload`, [agent.workspaceId || 'default', agent.id, agent.companyId || 'default', agent.name, agent.team || null, agent.status || 'registered', agent.runtimeStatus || null, agent.parentId || null, agent.credentialHash || null, agent.lastSeenAt || '', agent.createdAt || null, JSON.stringify(agent)]);
}

async function saveWithAudit(agent, audit, { create = false, expectedUpdatedAt = null, assessmentReviewReason = null, assessmentChange = null } = {}) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const workspaceId = agent.workspaceId || 'default';
    const company = await client.query('SELECT 1 FROM ag_companies WHERE workspace_id=$1 AND id=$2 FOR SHARE', [workspaceId, agent.companyId || 'default']);
    if (!company.rowCount) { const error = new Error('Unknown company in this workspace'); error.statusCode = 404; throw error; }
    if (agent.parentId) {
      if (agent.parentId === agent.id) { const error = new Error('An agent cannot be its own parent'); error.statusCode = 400; throw error; }
      const parent = await client.query('SELECT company_id FROM ag_agents WHERE workspace_id=$1 AND id=$2 FOR SHARE', [workspaceId, agent.parentId]);
      if (!parent.rowCount || parent.rows[0].company_id !== agent.companyId) { const error = new Error('Parent agent must belong to the same company'); error.statusCode = 400; throw error; }
    }
    const current = await client.query('SELECT updated_at FROM ag_agents WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [workspaceId, agent.id]);
    if (create && current.rowCount) { const error = new Error('Agent ID already exists in this workspace'); error.statusCode = 409; throw error; }
    if (!create && !current.rowCount) { const error = new Error('Agent not found'); error.statusCode = 404; throw error; }
    if (!create && expectedUpdatedAt && new Date(current.rows[0].updated_at).getTime() !== new Date(expectedUpdatedAt).getTime()) { const error = new Error('Agent changed since it was loaded. Refresh and retry your edit.'); error.statusCode = 409; throw error; }
    const now = agent.updatedAt || new Date().toISOString();
    if (create) {
      await client.query(`INSERT INTO ag_agents (workspace_id,id,company_id,name,team,status,runtime_status,parent_id,credential_hash,last_seen_at,created_at,updated_at,payload)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,'')::timestamptz,COALESCE($11::timestamptz,now()),$12::timestamptz,$13::jsonb)`,
      [workspaceId, agent.id, agent.companyId || 'default', agent.name, agent.team || null, agent.status || 'registered', agent.runtimeStatus || null, agent.parentId || null, agent.credentialHash || null, agent.lastSeenAt || '', agent.createdAt || null, now, JSON.stringify(agent)]);
    } else {
      await client.query(`UPDATE ag_agents SET company_id=$3,name=$4,team=$5,status=$6,runtime_status=$7,parent_id=$8,credential_hash=$9,last_seen_at=NULLIF($10,'')::timestamptz,updated_at=$11::timestamptz,payload=$12::jsonb WHERE workspace_id=$1 AND id=$2`,
      [workspaceId, agent.id, agent.companyId || 'default', agent.name, agent.team || null, agent.status || 'registered', agent.runtimeStatus || null, agent.parentId || null, agent.credentialHash || null, agent.lastSeenAt || '', now, JSON.stringify(agent)]);
    }
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Audit event ID already exists; agent change was not committed'); error.statusCode = 409; throw error; }
    let assessmentReviewAudit = null;
    if (!create && (assessmentReviewReason || assessmentChange)) {
      const currentAssessment = await client.query('SELECT id,payload FROM ag_assessments WHERE workspace_id=$1 AND agent_id=$2 ORDER BY updated_at DESC LIMIT 1 FOR UPDATE', [workspaceId, agent.id]);
      if (currentAssessment.rows[0]) {
        const changedAt = new Date().toISOString();
        const change = assessmentChange ? { ...assessmentChange, recordedAt: changedAt } : null;
        const pendingChanges = change ? [...(currentAssessment.rows[0].payload.pendingChanges || []), change].slice(-50) : (currentAssessment.rows[0].payload.pendingChanges || []);
        const payload = assessmentReviewReason
          ? { ...currentAssessment.rows[0].payload, status: 'review_required', reviewRequiredAt: changedAt, reviewRequiredReason: assessmentReviewReason, pendingChanges, updatedAt: changedAt }
          : { ...currentAssessment.rows[0].payload, pendingChanges, updatedAt: changedAt };
        await client.query('UPDATE ag_assessments SET status=$3,updated_at=$4::timestamptz,payload=$5::jsonb WHERE workspace_id=$1 AND id=$2', [workspaceId,currentAssessment.rows[0].id,payload.status || 'draft',changedAt,JSON.stringify(payload)]);
        assessmentReviewAudit = await appendEventWithClient(client, { ...audit, id: require('node:crypto').randomUUID(), eventType: assessmentReviewReason ? 'assessment.review_required' : 'assessment.change_recorded', kind: assessmentReviewReason ? 'block' : 'action', message: assessmentReviewReason ? `Risk assessment review required for ${agent.name}` : `Assessment-relevant change recorded for ${agent.name}`, assessmentId: currentAssessment.rows[0].id, reason: assessmentReviewReason || assessmentChange?.reason, changedFields: assessmentChange?.changedFields || [], changeDetails: assessmentChange?.details || null, createdAt: changedAt });
      }
    }
    return { agent: { ...agent, updatedAt: now }, audit: savedAudit, assessmentReviewAudit };
  });
}

async function saveManyWithAudit(agents, audits) {
  if (!usePostgres) return undefined;
  if (!Array.isArray(agents) || agents.length !== audits.length) throw new Error('Agents and audit events must have matching lengths');
  return postgresTransaction(async client => {
    const saved = [];
    for (let index = 0; index < agents.length; index++) {
      const agent = agents[index], workspaceId = agent.workspaceId || 'default';
      const company = await client.query('SELECT 1 FROM ag_companies WHERE workspace_id=$1 AND id=$2 FOR SHARE', [workspaceId, agent.companyId || 'default']);
      if (!company.rowCount) { const error = new Error(`Unknown company for agent ${agent.name}`); error.statusCode = 404; throw error; }
      if (agent.parentId) {
        const parent = await client.query('SELECT company_id FROM ag_agents WHERE workspace_id=$1 AND id=$2 FOR SHARE', [workspaceId, agent.parentId]);
        if (!parent.rowCount || parent.rows[0].company_id !== agent.companyId) { const error = new Error(`Parent agent for ${agent.name} must belong to the same company`); error.statusCode = 400; throw error; }
      }
      const current = await client.query('SELECT 1 FROM ag_agents WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [workspaceId, agent.id]);
      if (current.rowCount) { const error = new Error(`Agent ID ${agent.id} already exists in this workspace`); error.statusCode = 409; throw error; }
      await client.query(`INSERT INTO ag_agents (workspace_id,id,company_id,name,team,status,runtime_status,parent_id,credential_hash,last_seen_at,created_at,updated_at,payload)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,'')::timestamptz,COALESCE($11::timestamptz,now()),$12::timestamptz,$13::jsonb)`,
      [workspaceId, agent.id, agent.companyId || 'default', agent.name, agent.team || null, agent.status || 'registered', agent.runtimeStatus || null, agent.parentId || null, agent.credentialHash || null, agent.lastSeenAt || '', agent.createdAt || null, agent.updatedAt || new Date().toISOString(), JSON.stringify(agent)]);
      const audit = await appendEventWithClient(client, audits[index]);
      if (!audit.chainSequence) { const error = new Error('Audit event ID already exists; bulk agent changes were not committed'); error.statusCode = 409; throw error; }
      saved.push({ agent: { ...agent, updatedAt: agent.updatedAt || new Date().toISOString() }, audit });
    }
    return saved;
  });
}

async function deleteArchivedWithAudit(agent, audit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const current = await client.query('SELECT status,payload FROM ag_agents WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [agent.workspaceId, agent.id]);
    if (!current.rowCount) { const error = new Error('Agent not found'); error.statusCode = 404; throw error; }
    const stored = { ...current.rows[0].payload, status: current.rows[0].status };
    if (!stored.archived && current.rows[0].status !== 'archived') { const error = new Error('Only archived agents can be permanently deleted'); error.statusCode = 409; throw error; }
    for (const table of ['ag_telemetry_receipts','ag_budget_reservations','ag_assessment_revisions','ag_assessments','ag_governed_actions','ag_approvals','ag_policies','ag_alerts','ag_incidents']) await client.query(`DELETE FROM ${table} WHERE workspace_id=$1 AND agent_id=$2`, [agent.workspaceId, agent.id]);
    await client.query('DELETE FROM ag_agents WHERE workspace_id=$1 AND id=$2', [agent.workspaceId, agent.id]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Agent deletion audit event was not committed'); error.statusCode = 409; throw error; }
    return { audit: savedAudit };
  });
}

async function registerGatewayAgent(company, agent, companyAudit, agentAudit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const workspaceId = company.workspaceId || agent.workspaceId || 'default';
    const currentCompany = await client.query('SELECT workspace_id,id,name,gateway_credential_hash,created_at,updated_at,payload FROM ag_companies WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [workspaceId, company.id]);
    let storedCompany, companyCreated = false, savedCompanyAudit = null;
    if (currentCompany.rowCount) {
      const row = currentCompany.rows[0];
      storedCompany = { ...row.payload, workspaceId: row.workspace_id, id: row.id, name: row.name, gatewayCredentialHash: row.gateway_credential_hash || null, createdAt: row.created_at?.toISOString?.() || row.created_at };
    } else {
      storedCompany = { ...company, workspaceId };
      await client.query(`INSERT INTO ag_companies (workspace_id,id,name,gateway_credential_hash,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,COALESCE($5::timestamptz,now()),now(),$6::jsonb)`, [workspaceId, storedCompany.id, storedCompany.name, storedCompany.gatewayCredentialHash || null, storedCompany.createdAt || null, JSON.stringify(storedCompany)]);
      savedCompanyAudit = await appendEventWithClient(client, companyAudit);
      if (!savedCompanyAudit.chainSequence) { const error = new Error('Company audit event ID already exists; onboarding was not committed'); error.statusCode = 409; throw error; }
      companyCreated = true;
    }
    const candidate = { ...agent, workspaceId, companyId: storedCompany.id };
    if (candidate.parentId) {
      if (candidate.parentId === candidate.id) { const error = new Error('An agent cannot be its own parent'); error.statusCode = 400; throw error; }
      const parent = await client.query('SELECT company_id FROM ag_agents WHERE workspace_id=$1 AND id=$2 FOR SHARE', [workspaceId, candidate.parentId]);
      if (!parent.rowCount || parent.rows[0].company_id !== candidate.companyId) { const error = new Error('Parent agent must belong to the same company'); error.statusCode = 400; throw error; }
    }
    const existingAgent = await client.query('SELECT 1 FROM ag_agents WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [workspaceId, candidate.id]);
    if (existingAgent.rowCount) { const error = new Error('Agent ID already exists in this workspace'); error.statusCode = 409; throw error; }
    await client.query(`INSERT INTO ag_agents (workspace_id,id,company_id,name,team,status,runtime_status,parent_id,credential_hash,last_seen_at,created_at,updated_at,payload)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,'')::timestamptz,COALESCE($11::timestamptz,now()),$12::timestamptz,$13::jsonb)`,
    [workspaceId, candidate.id, candidate.companyId, candidate.name, candidate.team || null, candidate.status || 'registered', candidate.runtimeStatus || null, candidate.parentId || null, candidate.credentialHash || null, candidate.lastSeenAt || '', candidate.createdAt || null, candidate.updatedAt || new Date().toISOString(), JSON.stringify(candidate)]);
    const savedAudit = await appendEventWithClient(client, agentAudit);
    if (!savedAudit.chainSequence) { const error = new Error('Agent audit event ID already exists; onboarding was not committed'); error.statusCode = 409; throw error; }
    return { company: storedCompany, companyCreated, companyAudit: savedCompanyAudit, agent: candidate, audit: savedAudit };
  });
}

module.exports = { list, listCompanies, get, getCompany, upsert, upsertCompany, saveCompanyWithAudit, saveWithAudit, saveManyWithAudit, deleteArchivedWithAudit, registerGatewayAgent };
