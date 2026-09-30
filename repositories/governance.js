const { postgresQuery, postgresTransaction, usePostgres } = require('../storage');
const { auditHash } = require('../audit-integrity');

let auditWriteChain = Promise.resolve();
function asIso(value) { return value?.toISOString?.() || value || null; }
function policy(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, name: row.name, effect: row.effect, enabled: row.enabled, version: row.version, priority: row.priority, createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at) }; }
function approval(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, policyId: row.policy_id || null, status: row.status, action: row.action, actionRef: row.action_ref || null, createdAt: asIso(row.created_at), decidedAt: asIso(row.decided_at) }; }
function event(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id || null, kind: row.kind, eventType: row.event_type || null, actor: row.actor, message: row.message, createdAt: asIso(row.created_at), previousHash: row.previous_hash || null, eventHash: row.event_hash || null }; }
function assessment(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, status: row.status, owner: row.owner || null, reviewDueAt: asIso(row.review_due_at), createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at) }; }
function incident(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id || null, status: row.status, severity: row.severity, title: row.title, owner: row.owner || null, sourceEventId: row.source_event_id || null, createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at), resolvedAt: asIso(row.resolved_at) }; }
function alert(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, incidentId: row.incident_id || null, agentId: row.agent_id || null, status: row.status, severity: row.severity, title: row.title, acknowledgedBy: row.acknowledged_by || null, createdAt: asIso(row.created_at), acknowledgedAt: asIso(row.acknowledged_at) }; }
function alertDelivery(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, alertId: row.alert_id, channel: row.channel, status: row.status, attemptedAt: asIso(row.attempted_at), deliveredAt: asIso(row.delivered_at), httpStatus: row.http_status || null, errorMessage: row.error_message || null }; }
function governedAction(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, actionRef: row.action_ref, actionType: row.action_type, action: row.action, resource: row.resource, policyId: row.policy_id || null, policyVersion: row.policy_version || null, approvalId: row.approval_id || null, state: row.state, executionId: row.execution_id || null, createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at), claimedAt: asIso(row.claimed_at), completedAt: asIso(row.completed_at) }; }

async function appendEventWithClient(client, item) {
  const workspaceId = item.workspaceId || 'default';
  await client.query(`SELECT pg_advisory_xact_lock(hashtext('agentguard-audit'), hashtext($1))`, [workspaceId]);
  const previous = await client.query('SELECT event_hash FROM ag_audit_events WHERE workspace_id=$1 ORDER BY chain_sequence DESC LIMIT 1', [workspaceId]);
  const previousHash = previous.rows[0]?.event_hash || null;
  const eventHash = auditHash(previousHash, item, workspaceId);
  await client.query(`INSERT INTO ag_audit_events (workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8::timestamptz,now()),$9,$10,$11::jsonb) ON CONFLICT (workspace_id,id) DO NOTHING`, [workspaceId, item.id, item.agentId || null, item.kind || 'action', item.eventType || null, item.actor || 'system', item.message || 'AgentGuard event', item.createdAt || null, previousHash, eventHash, JSON.stringify(item)]);
}

async function upsertGovernedAction(item) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`INSERT INTO ag_governed_actions (workspace_id,id,agent_id,action_ref,action_type,action,resource,policy_id,policy_version,approval_id,state,execution_id,created_at,updated_at,claimed_at,completed_at,payload)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,COALESCE($13::timestamptz,now()),COALESCE($14::timestamptz,now()),NULLIF($15,'')::timestamptz,NULLIF($16,'')::timestamptz,$17::jsonb)
    ON CONFLICT (workspace_id,agent_id,action_ref) DO UPDATE SET approval_id=COALESCE(ag_governed_actions.approval_id,EXCLUDED.approval_id),updated_at=now(),payload=ag_governed_actions.payload || EXCLUDED.payload
    RETURNING *`, [item.workspaceId || 'default', item.id, item.agentId, item.actionRef, item.actionType, item.action, item.resource || '*', item.policyId || null, item.policyVersion || null, item.approvalId || null, item.state, item.executionId || null, item.createdAt || null, item.updatedAt || null, item.claimedAt || '', item.completedAt || '', JSON.stringify(item)]);
  return governedAction(result.rows[0]);
}

async function claimGovernedAction(criteria) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const result = await client.query(`SELECT ga.* FROM ag_governed_actions ga WHERE ga.workspace_id=$1 AND ga.agent_id=$2 AND ga.action_ref=$3 FOR UPDATE`, [criteria.workspaceId, criteria.agentId, criteria.actionRef]);
    if (!result.rows[0]) return { outcome: 'not_found' };
    const current = governedAction(result.rows[0]);
    if (current.actionType !== criteria.actionType || current.action !== criteria.action || current.resource !== (criteria.resource || '*')) return { outcome: 'mismatch' };
    if (['claimed','completed','failed'].includes(current.state)) return { outcome: 'duplicate', action: current };
    const approval = current.approvalId ? await client.query('SELECT status,payload FROM ag_approvals WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [criteria.workspaceId, current.approvalId]) : null;
    const status = approval?.rows[0]?.status;
    if (status !== 'approved') return { outcome: status === 'denied' ? 'denied' : 'not_approved', action: current };
    const executionId = criteria.executionId;
    const now = new Date().toISOString();
    const updated = await client.query(`UPDATE ag_governed_actions SET state='claimed',execution_id=$4,claimed_at=$5,updated_at=$5,payload=payload || $6::jsonb WHERE workspace_id=$1 AND agent_id=$2 AND action_ref=$3 RETURNING *`, [criteria.workspaceId, criteria.agentId, criteria.actionRef, executionId, now, JSON.stringify({ executionId, claimedAt: now })]);
    const item = { id: criteria.auditId, workspaceId: criteria.workspaceId, agentId: criteria.agentId, kind: 'action', eventType: 'execution.claimed', actor: `agent:${criteria.agentId}`, message: `Execution claimed: ${current.action}`, actionRef: current.actionRef, actionType: current.actionType, resource: current.resource, approvalId: current.approvalId, executionId, createdAt: now };
    await appendEventWithClient(client, item);
    return { outcome: 'claimed', action: governedAction(updated.rows[0]) };
  });
}

async function completeGovernedAction(criteria) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const result = await client.query('SELECT * FROM ag_governed_actions WHERE workspace_id=$1 AND execution_id=$2 FOR UPDATE', [criteria.workspaceId, criteria.executionId]);
    if (!result.rows[0]) return { outcome: 'not_found' };
    const current = governedAction(result.rows[0]);
    if (['completed','failed'].includes(current.state)) return { outcome: 'duplicate', action: current };
    if (current.state !== 'claimed' || current.agentId !== criteria.agentId) return { outcome: 'invalid_state', action: current };
    const state = criteria.success === false ? 'failed' : 'completed'; const now = new Date().toISOString();
    const payload = { result: criteria.result || null, error: criteria.error || null, completedAt: now };
    const updated = await client.query(`UPDATE ag_governed_actions SET state=$3,completed_at=$4,updated_at=$4,payload=payload || $5::jsonb WHERE workspace_id=$1 AND execution_id=$2 RETURNING *`, [criteria.workspaceId, criteria.executionId, state, now, JSON.stringify(payload)]);
    await appendEventWithClient(client, { id: criteria.auditId, workspaceId: criteria.workspaceId, agentId: criteria.agentId, kind: state === 'failed' ? 'block' : 'action', eventType: `execution.${state}`, actor: `agent:${criteria.agentId}`, message: `${state === 'failed' ? 'Execution failed' : 'Execution completed'}: ${current.action}`, actionRef: current.actionRef, approvalId: current.approvalId, executionId: criteria.executionId, result: criteria.result || null, error: criteria.error || null, createdAt: now });
    return { outcome: state, action: governedAction(updated.rows[0]) };
  });
}

async function listPolicies(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT workspace_id,id,name,effect,enabled,version,priority,created_at,updated_at,payload FROM ag_policies WHERE workspace_id=$1 ORDER BY priority DESC,created_at DESC', [workspaceId]); return result.rows.map(policy); }
async function getPolicy(id, workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT workspace_id,id,name,effect,enabled,version,priority,created_at,updated_at,payload FROM ag_policies WHERE id=$1 AND workspace_id=$2 LIMIT 1', [id, workspaceId]); return result.rows[0] ? policy(result.rows[0]) : null; }
async function listApprovals(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery(`SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload FROM ag_approvals WHERE workspace_id=$1 AND status='pending' ORDER BY created_at DESC`, [workspaceId]); return result.rows.map(approval); }
async function getApproval(id, workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload FROM ag_approvals WHERE id=$1 AND workspace_id=$2 LIMIT 1', [id, workspaceId]); return result.rows[0] ? approval(result.rows[0]) : null; }
async function findApprovalForAction(criteria, workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload
    FROM ag_approvals
    WHERE workspace_id=$1 AND agent_id=$2 AND action_ref=$3 AND action=$4 AND policy_id=$5
      AND COALESCE(payload->>'actionType','')=$6 AND COALESCE(payload->>'resource','*')=$7
      AND COALESCE((payload->>'policyVersion')::integer,0)=$8
    ORDER BY created_at DESC LIMIT 1`, [workspaceId, criteria.agentId, criteria.actionRef, criteria.action, criteria.policyId, criteria.actionType, criteria.resource || '*', criteria.policyVersion || 0]);
  return result.rows[0] ? approval(result.rows[0]) : null;
}
async function listEvents(workspaceId, limit = 250) { if (!usePostgres) return undefined; const result = await postgresQuery(`SELECT workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,payload FROM ag_audit_events WHERE workspace_id=$1 AND COALESCE(event_type,'') <> 'heartbeat' AND message !~* 'heartbeat|agent is online' ORDER BY created_at DESC LIMIT $2`, [workspaceId, limit]); return result.rows.map(event); }
async function listAssessments(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload FROM ag_assessments WHERE workspace_id=$1 ORDER BY updated_at DESC', [workspaceId]); return result.rows.map(assessment); }
async function getAssessment(agentId, workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload FROM ag_assessments WHERE agent_id=$1 AND workspace_id=$2 ORDER BY updated_at DESC LIMIT 1', [agentId, workspaceId]); return result.rows[0] ? assessment(result.rows[0]) : null; }
async function listIncidents(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery("SELECT workspace_id,id,agent_id,status,severity,title,owner,source_event_id,created_at,updated_at,resolved_at,payload FROM ag_incidents WHERE workspace_id=$1 ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'investigating' THEN 1 ELSE 2 END, updated_at DESC", [workspaceId]); return result.rows.map(incident); }
async function upsertIncident(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_incidents (workspace_id,id,agent_id,status,severity,title,owner,source_event_id,created_at,updated_at,resolved_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,now()),COALESCE($10::timestamptz,now()),NULLIF($11,'')::timestamptz,$12::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,severity=EXCLUDED.severity,title=EXCLUDED.title,owner=EXCLUDED.owner,updated_at=EXCLUDED.updated_at,resolved_at=EXCLUDED.resolved_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.agentId || null, item.status || 'open', item.severity || 'medium', item.title, item.owner || null, item.sourceEventId || null, item.createdAt || null, item.updatedAt || null, item.resolvedAt || '', JSON.stringify(item)]); }
async function listAlerts(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery("SELECT workspace_id,id,incident_id,agent_id,status,severity,title,acknowledged_by,created_at,acknowledged_at,payload FROM ag_alerts WHERE workspace_id=$1 ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, created_at DESC", [workspaceId]); return result.rows.map(alert); }
async function upsertAlert(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_alerts (workspace_id,id,incident_id,agent_id,status,severity,title,acknowledged_by,created_at,acknowledged_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,now()),NULLIF($10,'')::timestamptz,$11::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,acknowledged_by=EXCLUDED.acknowledged_by,acknowledged_at=EXCLUDED.acknowledged_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.incidentId || null, item.agentId || null, item.status || 'open', item.severity || 'medium', item.title, item.acknowledgedBy || null, item.createdAt || null, item.acknowledgedAt || '', JSON.stringify(item)]); }
async function listAlertDeliveries(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT workspace_id,id,alert_id,channel,status,attempted_at,delivered_at,http_status,error_message,payload FROM ag_alert_deliveries WHERE workspace_id=$1 ORDER BY attempted_at DESC', [workspaceId]); return result.rows.map(alertDelivery); }
async function upsertAlertDelivery(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_alert_deliveries (workspace_id,id,alert_id,channel,status,attempted_at,delivered_at,http_status,error_message,payload) VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz,now()),NULLIF($7,'')::timestamptz,$8,$9,$10::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,attempted_at=EXCLUDED.attempted_at,delivered_at=EXCLUDED.delivered_at,http_status=EXCLUDED.http_status,error_message=EXCLUDED.error_message,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.alertId, item.channel || 'webhook', item.status, item.attemptedAt || null, item.deliveredAt || '', item.httpStatus || null, item.errorMessage || null, JSON.stringify(item)]); }
async function exportEvidence(workspaceId, from, to, limit = 10000) {
  if (!usePostgres) return undefined;
  const params = [workspaceId, from, to, limit];
  const [agents, policies, approvals, governedActions, assessments, incidents, alerts, deliveries, events] = await Promise.all([
    postgresQuery(`SELECT (payload - 'credentialHash' #- '{connection,authHeader}') AS payload FROM ag_agents WHERE workspace_id=$1 ORDER BY created_at`, [workspaceId]),
    postgresQuery('SELECT payload FROM ag_policies WHERE workspace_id=$1 ORDER BY created_at', [workspaceId]),
    postgresQuery('SELECT payload FROM ag_approvals WHERE workspace_id=$1 AND created_at BETWEEN $2::timestamptz AND $3::timestamptz ORDER BY created_at', params.slice(0, 3)),
    postgresQuery("SELECT payload || jsonb_build_object('state',state,'executionId',execution_id,'claimedAt',claimed_at,'completedAt',completed_at) AS payload FROM ag_governed_actions WHERE workspace_id=$1 AND created_at BETWEEN $2::timestamptz AND $3::timestamptz ORDER BY created_at", params.slice(0, 3)),
    postgresQuery('SELECT payload FROM ag_assessments WHERE workspace_id=$1 ORDER BY created_at', [workspaceId]),
    postgresQuery('SELECT payload FROM ag_incidents WHERE workspace_id=$1 AND created_at BETWEEN $2::timestamptz AND $3::timestamptz ORDER BY created_at', params.slice(0, 3)),
    postgresQuery('SELECT payload FROM ag_alerts WHERE workspace_id=$1 AND created_at BETWEEN $2::timestamptz AND $3::timestamptz ORDER BY created_at', params.slice(0, 3)),
    postgresQuery('SELECT payload FROM ag_alert_deliveries WHERE workspace_id=$1 AND attempted_at BETWEEN $2::timestamptz AND $3::timestamptz ORDER BY attempted_at', params.slice(0, 3)),
    postgresQuery(`SELECT payload || jsonb_build_object('previousHash',previous_hash,'eventHash',event_hash,'chainSequence',chain_sequence) AS payload FROM ag_audit_events WHERE workspace_id=$1 AND created_at BETWEEN $2::timestamptz AND $3::timestamptz ORDER BY chain_sequence LIMIT $4`, params)
  ]);
  const values = result => result.rows.map(row => row.payload);
  return { agents: values(agents), policies: values(policies), approvals: values(approvals), governedActions: values(governedActions), assessments: values(assessments), incidents: values(incidents), alerts: values(alerts), alertDeliveries: values(deliveries), auditEvents: values(events) };
}
async function upsertAssessment(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_assessments (workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::timestamptz,COALESCE($7::timestamptz,now()),COALESCE($8::timestamptz,now()),$9::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET agent_id=EXCLUDED.agent_id,status=EXCLUDED.status,owner=EXCLUDED.owner,review_due_at=EXCLUDED.review_due_at,updated_at=EXCLUDED.updated_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.agentId, item.status || 'draft', item.owner || null, item.reviewDueAt || '', item.createdAt || null, item.updatedAt || null, JSON.stringify(item)]); }
async function upsertPolicy(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_policies (workspace_id,id,agent_id,name,effect,enabled,version,priority,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,now()),COALESCE($10::timestamptz,now()),$11::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET agent_id=EXCLUDED.agent_id,name=EXCLUDED.name,effect=EXCLUDED.effect,enabled=EXCLUDED.enabled,version=EXCLUDED.version,priority=EXCLUDED.priority,updated_at=EXCLUDED.updated_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.agentId, item.name, item.effect, Boolean(item.enabled), item.version || 1, item.priority || 100, item.createdAt || null, item.updatedAt || null, JSON.stringify(item)]); }
async function upsertApproval(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_approvals (workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8::timestamptz,now()),NULLIF($9,'')::timestamptz,$10::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,decided_at=EXCLUDED.decided_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.agentId, item.policyId || null, item.status || 'pending', item.action, item.actionRef || null, item.createdAt || null, item.decidedAt || '', JSON.stringify(item)]); }
async function decideApproval(id, workspaceId, decision) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const locked = await client.query('SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload FROM ag_approvals WHERE id=$1 AND workspace_id=$2 FOR UPDATE', [id, workspaceId]);
    if (!locked.rows[0] || locked.rows[0].status !== 'pending') return null;
    const current = approval(locked.rows[0]);
    const updated = { ...current, ...decision, status: decision.status, decidedAt: decision.decidedAt };
    const result = await client.query(`UPDATE ag_approvals SET status=$3,decided_at=$4::timestamptz,payload=$5::jsonb
      WHERE id=$1 AND workspace_id=$2 AND status='pending'
      RETURNING workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload`, [id, workspaceId, updated.status, updated.decidedAt, JSON.stringify(updated)]);
    return result.rows[0] ? approval(result.rows[0]) : null;
  });
}
async function expireDueApprovals(limit = 100) {
  if (!usePostgres) return [];
  return postgresTransaction(async client => {
    const due = await client.query(`SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload
      FROM ag_approvals WHERE status='pending' AND NULLIF(payload->>'expiresAt','')::timestamptz <= now()
      ORDER BY NULLIF(payload->>'expiresAt','')::timestamptz LIMIT $1 FOR UPDATE SKIP LOCKED`, [limit]);
    const expired = [];
    for (const row of due.rows) {
      const current = approval(row); const decidedAt = new Date().toISOString();
      const updated = { ...current, status: 'denied', decision: 'expired', decidedAt, decidedBy: 'system', rationale: 'Approval expired before a reviewer decided.' };
      const changed = await client.query(`UPDATE ag_approvals SET status='denied',decided_at=$3::timestamptz,payload=$4::jsonb
        WHERE workspace_id=$1 AND id=$2 AND status='pending' RETURNING workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload`, [row.workspace_id, row.id, decidedAt, JSON.stringify(updated)]);
      if (!changed.rows[0]) continue;
      await client.query(`UPDATE ag_governed_actions SET state='expired',updated_at=$3::timestamptz,payload=payload || $4::jsonb
        WHERE workspace_id=$1 AND approval_id=$2 AND state IN ('awaiting_approval','approved')`, [row.workspace_id, row.id, decidedAt, JSON.stringify({ state: 'expired', expiredAt: decidedAt })]);
      const eventId = require('node:crypto').randomUUID();
      const message = `Approval expired: ${row.action}`;
      await appendEventWithClient(client, { id: eventId, workspaceId: row.workspace_id, agentId: row.agent_id, kind: 'block', eventType: 'approval.expired', actor: 'system', message, approvalId: row.id, actionRef: row.action_ref, policyId: row.policy_id, createdAt: decidedAt });
      const incidentId = require('node:crypto').randomUUID();
      const incident = { id: incidentId, workspaceId: row.workspace_id, agentId: row.agent_id, status: 'open', severity: 'medium', title: message, sourceEventId: eventId, createdAt: decidedAt, updatedAt: decidedAt, timeline: [{ at: decidedAt, actor: 'system', note: 'Approval expired without reviewer action; follow-up required.' }] };
      await client.query(`INSERT INTO ag_incidents (workspace_id,id,agent_id,status,severity,title,source_event_id,created_at,updated_at,payload) VALUES ($1,$2,$3,'open','medium',$4,$5,$6::timestamptz,$6::timestamptz,$7::jsonb)`, [row.workspace_id, incident.id, row.agent_id, incident.title, eventId, decidedAt, JSON.stringify(incident)]);
      const alert = { id: require('node:crypto').randomUUID(), workspaceId: row.workspace_id, incidentId, agentId: row.agent_id, status: 'open', severity: 'medium', title: `Approval expired: ${row.action}`, createdAt: decidedAt, channels: ['in-app'] };
      await client.query(`INSERT INTO ag_alerts (workspace_id,id,incident_id,agent_id,status,severity,title,created_at,payload) VALUES ($1,$2,$3,$4,'open','medium',$5,$6::timestamptz,$7::jsonb)`, [row.workspace_id, alert.id, incidentId, row.agent_id, alert.title, decidedAt, JSON.stringify(alert)]);
      expired.push({ ...approval(changed.rows[0]), incident, alert });
    }
    return expired;
  });
}
function appendEvent(item) {
  if (!usePostgres) return Promise.resolve();
  const write = auditWriteChain.then(() => postgresTransaction(async client => {
    await appendEventWithClient(client, item);
  }));
  auditWriteChain = write.catch(() => {});
  return write;
}
function flushAudit() { return auditWriteChain; }

module.exports = { listPolicies, getPolicy, findApprovalForAction, decideApproval, expireDueApprovals, listApprovals, getApproval, listEvents, listAssessments, getAssessment, listIncidents, upsertIncident, listAlerts, upsertAlert, listAlertDeliveries, upsertAlertDelivery, exportEvidence, upsertAssessment, upsertPolicy, upsertApproval, upsertGovernedAction, claimGovernedAction, completeGovernedAction, appendEvent, flushAudit };
