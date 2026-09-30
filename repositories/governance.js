const { postgresQuery, postgresTransaction, usePostgres } = require('../storage');
const { auditHash } = require('../audit-integrity');

let auditWriteChain = Promise.resolve();
function asIso(value) { return value?.toISOString?.() || value || null; }
function policy(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, name: row.name, effect: row.effect, enabled: row.enabled, version: row.version, priority: row.priority, createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at) }; }
function approval(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, policyId: row.policy_id || null, status: row.status, action: row.action, actionRef: row.action_ref || null, createdAt: asIso(row.created_at), decidedAt: asIso(row.decided_at) }; }
function event(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id || null, kind: row.kind, eventType: row.event_type || null, actor: row.actor, message: row.message, createdAt: asIso(row.created_at), previousHash: row.previous_hash || null, eventHash: row.event_hash || null, chainSequence: Number(row.chain_sequence) || null }; }
function assessment(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, status: row.status, owner: row.owner || null, reviewDueAt: asIso(row.review_due_at), createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at) }; }
function incident(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id || null, status: row.status, severity: row.severity, title: row.title, owner: row.owner || null, sourceEventId: row.source_event_id || null, createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at), resolvedAt: asIso(row.resolved_at) }; }
function alert(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, incidentId: row.incident_id || null, agentId: row.agent_id || null, status: row.status, severity: row.severity, title: row.title, acknowledgedBy: row.acknowledged_by || null, createdAt: asIso(row.created_at), acknowledgedAt: asIso(row.acknowledged_at) }; }
function alertDelivery(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, alertId: row.alert_id, channel: row.channel, status: row.status, attemptedAt: asIso(row.attempted_at), deliveredAt: asIso(row.delivered_at), httpStatus: row.http_status || null, errorMessage: row.error_message || null, outboxStatus: row.outbox_status || null, attempts: Number(row.outbox_attempts ?? row.payload?.attempt) || 0, retryAt: asIso(row.retry_at) }; }
function governedAction(row) { return { ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, actionRef: row.action_ref, actionType: row.action_type, action: row.action, resource: row.resource, policyId: row.policy_id || null, policyVersion: row.policy_version || null, approvalId: row.approval_id || null, state: row.state, executionId: row.execution_id || null, createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at), claimedAt: asIso(row.claimed_at), completedAt: asIso(row.completed_at) }; }

async function appendEventWithClient(client, item) {
  const workspaceId = item.workspaceId || 'default';
  await client.query(`SELECT pg_advisory_xact_lock(hashtext('agentguard-audit'), hashtext($1))`, [workspaceId]);
  const previous = await client.query('SELECT event_hash FROM ag_audit_events WHERE workspace_id=$1 ORDER BY chain_sequence DESC LIMIT 1', [workspaceId]);
  const previousHash = previous.rows[0]?.event_hash || null;
  const eventHash = auditHash(previousHash, item, workspaceId);
  const inserted = await client.query(`INSERT INTO ag_audit_events (workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8::timestamptz,now()),$9,$10,$11::jsonb) ON CONFLICT (workspace_id,id) DO NOTHING RETURNING chain_sequence`, [workspaceId, item.id, item.agentId || null, item.kind || 'action', item.eventType || null, item.actor || 'system', item.message || 'AgentGuard event', item.createdAt || null, previousHash, eventHash, JSON.stringify(item)]);
  return { ...item, workspaceId, previousHash, eventHash, chainSequence: inserted.rows[0]?.chain_sequence || null };
}

async function insertApprovalNotification(client, approvalItem) {
  const notification = {
    id: require('node:crypto').randomUUID(), workspaceId: approvalItem.workspaceId || 'default',
    incidentId: null, agentId: approvalItem.agentId || null, status: 'open',
    severity: ['low', 'medium', 'high', 'critical'].includes(String(approvalItem.risk || '').toLowerCase()) ? String(approvalItem.risk).toLowerCase() : 'medium', title: `Approval required: ${approvalItem.action}`,
    createdAt: new Date().toISOString(), channels: ['in-app', 'webhook'],
    notificationType: 'approval.required', approvalId: approvalItem.id,
    action: approvalItem.action, actionType: approvalItem.actionType || null,
    resource: approvalItem.resource || null, expiresAt: approvalItem.expiresAt || null
  };
  await client.query(`INSERT INTO ag_alerts (workspace_id,id,incident_id,agent_id,status,severity,title,created_at,payload)
    VALUES ($1,$2,NULL,$3,'open',$4,$5,$6::timestamptz,$7::jsonb)`,
  [notification.workspaceId, notification.id, notification.agentId, notification.severity, notification.title, notification.createdAt, JSON.stringify(notification)]);
  await client.query(`INSERT INTO ag_alert_outbox (workspace_id,alert_id,channel,status)
    VALUES ($1,$2,'webhook','queued') ON CONFLICT (workspace_id,alert_id,channel) DO NOTHING`, [notification.workspaceId, notification.id]);
  return notification;
}

async function insertGovernanceSignal(client, item, severity = 'medium') {
  const audit = await appendEventWithClient(client, item);
  if (!audit.chainSequence) { const error = new Error('Governance signal audit event ID already exists'); error.statusCode = 409; throw error; }
  const message = item.message || 'Governance policy blocked an action';
  const incident = { id: require('node:crypto').randomUUID(), workspaceId: item.workspaceId || 'default', agentId: item.agentId || null, status: 'open', severity, title: message, sourceEventId: item.id, createdAt: item.createdAt, updatedAt: item.createdAt, timeline: [{ at: item.createdAt, actor: item.actor || 'system', note: message }] };
  await client.query(`INSERT INTO ag_incidents (workspace_id,id,agent_id,status,severity,title,source_event_id,created_at,updated_at,payload) VALUES ($1,$2,$3,'open',$4,$5,$6,$7::timestamptz,$7::timestamptz,$8::jsonb)`, [incident.workspaceId, incident.id, incident.agentId, severity, incident.title, item.id, item.createdAt, JSON.stringify(incident)]);
  const isExpiredApproval = item.eventType === 'approval.expired' && item.approvalId;
  const alert = { id: require('node:crypto').randomUUID(), workspaceId: incident.workspaceId, incidentId: incident.id, agentId: incident.agentId, status: 'open', severity, title: message, createdAt: item.createdAt, channels: isExpiredApproval ? ['in-app', 'webhook'] : ['in-app'], ...(isExpiredApproval ? { notificationType: 'approval.expired', approvalId: item.approvalId, action: item.action || message.replace(/^Approval expired: /, ''), actionType: item.actionType || null, resource: item.resource || null } : {}) };
  await client.query(`INSERT INTO ag_alerts (workspace_id,id,incident_id,agent_id,status,severity,title,created_at,payload) VALUES ($1,$2,$3,$4,'open',$5,$6,$7::timestamptz,$8::jsonb)`, [alert.workspaceId, alert.id, alert.incidentId, alert.agentId, severity, alert.title, alert.createdAt, JSON.stringify(alert)]);
  if (isExpiredApproval) await client.query(`INSERT INTO ag_alert_outbox (workspace_id,alert_id,channel,status) VALUES ($1,$2,'webhook','queued') ON CONFLICT (workspace_id,alert_id,channel) DO NOTHING`, [alert.workspaceId, alert.id]);
  return { audit, incident, alert };
}
async function recordGovernanceSignal(item, severity = 'medium') {
  if (!usePostgres) return undefined;
  return postgresTransaction(client => insertGovernanceSignal(client, item, severity));
}

async function writeGovernedAction(client, item) {
  const result = await client.query(`INSERT INTO ag_governed_actions (workspace_id,id,agent_id,action_ref,action_type,action,resource,policy_id,policy_version,approval_id,state,execution_id,created_at,updated_at,claimed_at,completed_at,payload)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,COALESCE($12::timestamptz,now()),COALESCE($12::timestamptz,now()),NULL,NULL,$13::jsonb)
    ON CONFLICT (workspace_id,agent_id,action_ref) DO UPDATE SET approval_id=COALESCE(ag_governed_actions.approval_id,EXCLUDED.approval_id),updated_at=now(),payload=ag_governed_actions.payload || EXCLUDED.payload
    RETURNING *`, [item.workspaceId, item.id, item.agentId, item.actionRef, item.actionType, item.action, item.resource || '*', item.policyId || null, item.policyVersion || null, item.approvalId || null, item.state, item.createdAt, JSON.stringify(item)]);
  return governedAction(result.rows[0]);
}

async function reserveDailyBudget(client, { workspaceId, agentId, policy, input }) {
  const maxTokens = Number(policy.dailyMaxTokens || 0);
  const maxCost = Number(policy.dailyMaxCostUsd || 0);
  const maxActions = Number(policy.dailyMaxActions || 0);
  if (!maxTokens && !maxCost && !maxActions) return null;
  const tokens = Number(input.estimatedTokens);
  const cost = Number(input.estimatedCostUsd);
  if (maxTokens && (!Number.isFinite(tokens) || tokens < 0)) return `Token estimate is required for the daily limit (${maxTokens})`;
  if (maxCost && (!Number.isFinite(cost) || cost < 0)) return `Cost estimate is required for the daily limit ($${maxCost})`;
  const existing = await client.query(`SELECT 1 FROM ag_budget_reservations WHERE workspace_id=$1 AND policy_id=$2 AND agent_id=$3 AND action_ref=$4 AND budget_day=CURRENT_DATE AND released_at IS NULL`, [workspaceId, policy.id, agentId, input.actionRef]);
  if (existing.rowCount) return null;
  const used = await client.query(`SELECT COALESCE(sum(reserved_tokens),0)::bigint AS tokens, COALESCE(sum(reserved_cost_usd),0)::numeric AS cost, COALESCE(sum(reserved_actions),0)::int AS actions FROM ag_budget_reservations WHERE workspace_id=$1 AND policy_id=$2 AND agent_id=$3 AND budget_day=CURRENT_DATE AND released_at IS NULL`, [workspaceId, policy.id, agentId]);
  const current = used.rows[0];
  if (maxTokens && Number(current.tokens) + tokens > maxTokens) return `Daily token budget exceeded (${current.tokens} reserved + ${tokens} requested; limit ${maxTokens})`;
  if (maxCost && Number(current.cost) + cost > maxCost) return `Daily cost budget exceeded ($${current.cost} reserved + $${cost} requested; limit $${maxCost})`;
  if (maxActions && Number(current.actions) + 1 > maxActions) return `Daily action budget exceeded (${current.actions} reserved + 1 requested; limit ${maxActions})`;
  await client.query(`INSERT INTO ag_budget_reservations (workspace_id,policy_id,agent_id,action_ref,reserved_tokens,reserved_cost_usd,reserved_actions) VALUES ($1,$2,$3,$4,$5,$6,1)`, [workspaceId, policy.id, agentId, input.actionRef, Number.isFinite(tokens) ? tokens : 0, Number.isFinite(cost) ? cost : 0]);
  return null;
}

// Evaluate an action and persist its agent activity, decision, approval/action
// state, audit-chain entry, and any resulting incident in one database commit.
async function checkGovernedAction(criteria) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const locked = await client.query(`SELECT workspace_id,id,company_id,name,team,status,runtime_status,parent_id,last_seen_at,payload
      FROM ag_agents WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, [criteria.workspaceId, criteria.agentId]);
    if (!locked.rows[0]) return { outcome: 'not_found' };
    const row = locked.rows[0];
    const agent = { ...row.payload, workspaceId: row.workspace_id, id: row.id, companyId: row.company_id, name: row.name, team: row.team, status: row.status, runtimeStatus: row.runtime_status, parentId: row.parent_id, lastSeenAt: asIso(row.last_seen_at) };
    if (agent.archived) return { outcome: 'archived' };
    const permission = criteria.toolPermission(agent, criteria.input);
    const now = new Date().toISOString();
    const input = criteria.input;
    const common = { id: require('node:crypto').randomUUID(), workspaceId: criteria.workspaceId, agentId: criteria.agentId, actionRef: input.actionRef, actionType: input.actionType, resource: criteria.resource, createdAt: now };
    if (!permission.allowed) {
      const reason = permission.tool ? `Tool “${permission.tool}” is not granted to this agent.` : 'Tool call is missing its tool name.';
      const signals = await insertGovernanceSignal(client, { ...common, kind: 'block', eventType: 'tool.permission_denied', actor: `agent:${criteria.agentId}`, message: `Tool permission denied: ${reason}`, tool: permission.tool, grantedTools: permission.grants || [] });
      return { outcome: 'block', decision: 'block', reason, permission: { tool: permission.tool, grantedTools: permission.grants || [] }, agent, ...signals };
    }

    Object.assign(agent, { status: 'healthy', lastSeenAt: now, lastActivityAt: now, runtimeStatus: 'running', currentTask: { id: input.actionRef, name: input.action } });
    await client.query(`UPDATE ag_agents SET status='healthy',runtime_status='running',last_seen_at=$3::timestamptz,updated_at=$3::timestamptz,payload=payload || $4::jsonb WHERE workspace_id=$1 AND id=$2`, [criteria.workspaceId, criteria.agentId, now, JSON.stringify({ status: 'healthy', lastSeenAt: now, lastActivityAt: now, runtimeStatus: 'running', currentTask: agent.currentTask })]);

    const policyRows = await client.query(`SELECT workspace_id,id,name,effect,enabled,version,priority,created_at,updated_at,payload
      FROM ag_policies WHERE workspace_id=$1 AND enabled=true ORDER BY priority DESC,created_at DESC FOR SHARE`, [criteria.workspaceId]);
    const policies = policyRows.rows.map(policy);
    const matched = criteria.matchingPolicy(policies, criteria.workspaceId, criteria.agentId, input.actionType, criteria.resource);
    const explanation = matched ? null : 'No enabled policy matched; default allow applies.';
    let budgetReason = matched ? criteria.exceedsBudget(matched, input) : null;
    if (!budgetReason && matched && matched.effect !== 'block') budgetReason = await reserveDailyBudget(client, { workspaceId: criteria.workspaceId, agentId: criteria.agentId, policy: matched, input });
    if (!matched || matched.effect === 'allow') {
      const message = matched ? `Allowed by ${matched.name}: ${input.action}` : `Allowed by default: ${input.action}`;
      const audit = await appendEventWithClient(client, { ...common, kind: 'action', eventType: 'policy.allowed', actor: `agent:${criteria.agentId}`, message, action: input.action, policyId: matched?.id || null, policyVersion: matched?.version || null, estimatedTokens: input.estimatedTokens ?? null, estimatedCostUsd: input.estimatedCostUsd ?? null });
      return { outcome: 'allow', decision: 'allow', policyId: matched?.id || null, policy: matched, reason: explanation, agent, audit };
    }

    if (budgetReason || matched.effect === 'block') {
      const eventType = budgetReason ? 'policy.budget_blocked' : 'policy.blocked';
      const message = budgetReason ? `Budget blocked by ${matched.name}: ${input.action} — ${budgetReason}` : `Blocked by ${matched.name}: ${input.action}`;
      const signals = await insertGovernanceSignal(client, { ...common, kind: 'block', eventType, actor: `agent:${criteria.agentId}`, message, action: input.action, policyId: matched.id, policyVersion: matched.version, estimatedTokens: input.estimatedTokens ?? null, estimatedCostUsd: input.estimatedCostUsd ?? null }, budgetReason ? 'high' : 'medium');
      return { outcome: 'block', decision: 'block', policyId: matched.id, policy: matched.name, reason: budgetReason || undefined, agent, ...signals };
    }

    const existingResult = await client.query(`SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload
      FROM ag_approvals WHERE workspace_id=$1 AND agent_id=$2 AND action_ref=$3 AND action=$4 AND policy_id=$5
        AND COALESCE(payload->>'actionType','')=$6 AND COALESCE(payload->>'resource','*')=$7
        AND COALESCE((payload->>'policyVersion')::integer,0)=$8
      ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, [criteria.workspaceId, criteria.agentId, input.actionRef, input.action, matched.id, input.actionType, criteria.resource, matched.version || 0]);
    let existing = existingResult.rows[0] ? approval(existingResult.rows[0]) : null;
    if (existing?.status === 'pending' && existing.expiresAt && new Date(existing.expiresAt).getTime() <= Date.now()) {
      const expiredAt = new Date().toISOString();
      const updated = { ...existing, status: 'denied', decision: 'expired', decidedAt: expiredAt, decidedBy: 'system', rationale: 'Approval expired before the action resumed.' };
      const saved = await client.query(`UPDATE ag_approvals SET status='denied',decided_at=$3::timestamptz,payload=$4::jsonb WHERE workspace_id=$1 AND id=$2 AND status='pending' RETURNING workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload`, [criteria.workspaceId, existing.id, expiredAt, JSON.stringify(updated)]);
      await client.query(`UPDATE ag_governed_actions SET state='expired',updated_at=$3::timestamptz,payload=payload || $4::jsonb WHERE workspace_id=$1 AND approval_id=$2 AND state IN ('awaiting_approval','approved')`, [criteria.workspaceId, existing.id, expiredAt, JSON.stringify({ state: 'expired', expiredAt })]);
      const signals = await insertGovernanceSignal(client, { ...common, createdAt: expiredAt, kind: 'block', eventType: 'approval.expired', actor: 'system', message: `Approval expired: ${existing.action}`, action: existing.action, actionType: existing.actionType, resource: existing.resource, approvalId: existing.id, policyId: existing.policyId }, 'medium');
      return { outcome: 'block', decision: 'block', approval: saved.rows[0] ? approval(saved.rows[0]) : updated, reason: 'Approval expired; reviewer action is no longer valid', agent, ...signals };
    }
    if (existing?.status === 'approved') {
      const governed = await writeGovernedAction(client, { ...common, id: require('node:crypto').randomUUID(), action: input.action, policyId: matched.id, policyVersion: matched.version, approvalId: existing.id, state: 'approved' });
      return { outcome: 'ready_to_execute', decision: 'ready_to_execute', approvalId: existing.id, claimRequired: true, agent, governedAction: governed };
    }
    if (existing?.status === 'denied') return { outcome: 'block', decision: 'block', approvalId: existing.id, policy: existing.risk, agent };

    if (existing?.status === 'pending') {
      const governed = await writeGovernedAction(client, { ...common, id: require('node:crypto').randomUUID(), action: input.action, policyId: matched.id, policyVersion: matched.version, approvalId: existing.id, state: 'awaiting_approval', createdAt: existing.createdAt });
      return { outcome: 'awaiting_approval', decision: 'awaiting_approval', approvalId: existing.id, agent, governedAction: governed };
    }

    const createdAt = now;
    const pending = { id: require('node:crypto').randomUUID(), workspaceId: criteria.workspaceId, companyId: agent.companyId || 'default', agentId: criteria.agentId, actionType: input.actionType, action: input.action, resource: criteria.resource, risk: matched.name, actionRef: input.actionRef, policyId: matched.id, policyVersion: matched.version, status: 'pending', createdAt, expiresAt: new Date(Date.now() + criteria.approvalTtlMs).toISOString() };
    const inserted = await client.query(`INSERT INTO ag_approvals (workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,payload) VALUES ($1,$2,$3,$4,'pending',$5,$6,$7::timestamptz,$8::jsonb) RETURNING workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload`, [criteria.workspaceId, pending.id, pending.agentId, pending.policyId, pending.action, pending.actionRef, createdAt, JSON.stringify(pending)]);
    const createdApproval = approval(inserted.rows[0]);
    const governed = await writeGovernedAction(client, { ...common, id: require('node:crypto').randomUUID(), action: input.action, policyId: matched.id, policyVersion: matched.version, approvalId: pending.id, state: 'awaiting_approval' });
    const audit = await appendEventWithClient(client, { ...common, kind: 'approval', eventType: 'approval.required', actor: `agent:${criteria.agentId}`, message: `Approval required by ${matched.name}: ${pending.action}`, action: pending.action, approvalId: pending.id, policyId: matched.id, policyVersion: matched.version, estimatedTokens: input.estimatedTokens ?? null, estimatedCostUsd: input.estimatedCostUsd ?? null });
    const notification = await insertApprovalNotification(client, createdApproval);
    return { outcome: 'awaiting_approval', decision: 'awaiting_approval', approvalId: pending.id, approval: createdApproval, governedAction: governed, agent, audit, alert: notification };
  });
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

async function listUncertainGovernedActions(workspaceId, minimumAgeMs = 300_000) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`SELECT workspace_id,id,agent_id,action_ref,action_type,action,resource,approval_id,state,execution_id,claimed_at
    FROM ag_governed_actions WHERE workspace_id=$1 AND state='claimed'
      AND claimed_at <= now() - ($2::bigint * interval '1 millisecond')
    ORDER BY claimed_at ASC LIMIT 100`, [workspaceId, minimumAgeMs]);
  return result.rows.map(row => ({ workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, actionRef: row.action_ref, actionType: row.action_type, action: row.action, resource: row.resource, approvalId: row.approval_id, state: row.state, executionId: row.execution_id, claimedAt: asIso(row.claimed_at) }));
}

async function reconcileGovernedAction(criteria) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const result = await client.query(`SELECT workspace_id,id,agent_id,action_ref,action_type,action,resource,approval_id,state,execution_id,claimed_at
      FROM ag_governed_actions WHERE workspace_id=$1 AND execution_id=$2 FOR UPDATE`, [criteria.workspaceId, criteria.executionId]);
    if (!result.rows[0]) return { outcome: 'not_found' };
    const current = result.rows[0];
    if (current.state !== 'claimed') return { outcome: 'already_resolved', state: current.state };
    const ageMs = Date.now() - new Date(current.claimed_at).getTime();
    if (ageMs < criteria.minimumAgeMs) return { outcome: 'too_recent', ageMs };
    if (!['completed', 'not_executed'].includes(criteria.outcome)) return { outcome: 'invalid_outcome' };
    const now = new Date().toISOString();
    const state = criteria.outcome === 'completed' ? 'completed' : 'failed';
    const reconciliation = { outcome: criteria.outcome, evidence: criteria.evidence, reviewer: criteria.reviewer, reconciledAt: now };
    const payload = { reconciliation, ...(criteria.outcome === 'completed' ? { result: criteria.result || { evidence: criteria.evidence } } : { error: 'Reviewer confirmed the downstream action was not executed.' }) };
    const updated = await client.query(`UPDATE ag_governed_actions SET state=$3,completed_at=$4::timestamptz,updated_at=$4::timestamptz,payload=payload || $5::jsonb
      WHERE workspace_id=$1 AND execution_id=$2 AND state='claimed' RETURNING *`, [criteria.workspaceId, criteria.executionId, state, now, JSON.stringify(payload)]);
    if (!updated.rows[0]) return { outcome: 'already_resolved' };
    const audit = await appendEventWithClient(client, {
      id: require('node:crypto').randomUUID(), workspaceId: criteria.workspaceId, agentId: current.agent_id,
      kind: state === 'failed' ? 'block' : 'action', eventType: 'execution.reconciled', actor: criteria.reviewer,
      message: `Uncertain execution manually reconciled as ${criteria.outcome}: ${current.action}`,
      actionRef: current.action_ref, actionType: current.action_type, resource: current.resource,
      approvalId: current.approval_id, executionId: current.execution_id, reconciliation,
      result: criteria.outcome === 'completed' ? payload.result : null, createdAt: now,
    });
    return { outcome: 'reconciled', state, audit, action: governedAction(updated.rows[0]) };
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
async function listEvents(workspaceId, limit = 250) { if (!usePostgres) return undefined; const result = await postgresQuery(`SELECT workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,chain_sequence,payload FROM ag_audit_events WHERE workspace_id=$1 AND COALESCE(event_type,'') <> 'heartbeat' AND message !~* 'heartbeat|agent is online' ORDER BY chain_sequence DESC LIMIT $2`, [workspaceId, limit]); return result.rows.map(event); }
async function listAssessments(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload FROM ag_assessments WHERE workspace_id=$1 ORDER BY updated_at DESC', [workspaceId]); return result.rows.map(assessment); }
async function getAssessment(agentId, workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload FROM ag_assessments WHERE agent_id=$1 AND workspace_id=$2 ORDER BY updated_at DESC LIMIT 1', [agentId, workspaceId]); return result.rows[0] ? assessment(result.rows[0]) : null; }
async function listAssessmentRevisions(agentId, workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery('SELECT version,scoring_model,score,reviewer,rationale,created_at,payload FROM ag_assessment_revisions WHERE workspace_id=$1 AND agent_id=$2 ORDER BY version DESC', [workspaceId, agentId]); return result.rows.map(row => ({ ...row.payload, version: row.version, scoringModel: row.scoring_model, score: row.score, reviewer: row.reviewer, rationale: row.rationale, createdAt: asIso(row.created_at) })); }
async function listIncidents(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery("SELECT workspace_id,id,agent_id,status,severity,title,owner,source_event_id,created_at,updated_at,resolved_at,payload FROM ag_incidents WHERE workspace_id=$1 ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'investigating' THEN 1 ELSE 2 END, updated_at DESC", [workspaceId]); return result.rows.map(incident); }
async function upsertIncident(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_incidents (workspace_id,id,agent_id,status,severity,title,owner,source_event_id,created_at,updated_at,resolved_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,now()),COALESCE($10::timestamptz,now()),NULLIF($11,'')::timestamptz,$12::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,severity=EXCLUDED.severity,title=EXCLUDED.title,owner=EXCLUDED.owner,updated_at=EXCLUDED.updated_at,resolved_at=EXCLUDED.resolved_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.agentId || null, item.status || 'open', item.severity || 'medium', item.title, item.owner || null, item.sourceEventId || null, item.createdAt || null, item.updatedAt || null, item.resolvedAt || '', JSON.stringify(item)]); }
async function saveIncidentWithAudit(item, audit, expectedUpdatedAt) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const current = await client.query('SELECT workspace_id,id,agent_id,status,severity,title,owner,source_event_id,created_at,updated_at,resolved_at,payload FROM ag_incidents WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [item.workspaceId || 'default', item.id]);
    if (!current.rows[0]) return { outcome: 'not_found' };
    if (expectedUpdatedAt && new Date(current.rows[0].updated_at).getTime() !== new Date(expectedUpdatedAt).getTime()) return { outcome: 'stale' };
    await client.query(`UPDATE ag_incidents SET status=$3,severity=$4,title=$5,owner=$6,updated_at=$7::timestamptz,resolved_at=NULLIF($8,'')::timestamptz,payload=$9::jsonb WHERE workspace_id=$1 AND id=$2`, [item.workspaceId || 'default', item.id, item.status, item.severity, item.title, item.owner || null, item.updatedAt, item.resolvedAt || '', JSON.stringify(item)]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Incident audit event ID already exists; update was not committed'); error.statusCode = 409; throw error; }
    return { outcome: 'updated', incident: item, audit: savedAudit };
  });
}
async function listAlerts(workspaceId) { if (!usePostgres) return undefined; const result = await postgresQuery("SELECT workspace_id,id,incident_id,agent_id,status,severity,title,acknowledged_by,created_at,acknowledged_at,payload FROM ag_alerts WHERE workspace_id=$1 ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, created_at DESC", [workspaceId]); return result.rows.map(alert); }
async function upsertAlert(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_alerts (workspace_id,id,incident_id,agent_id,status,severity,title,acknowledged_by,created_at,acknowledged_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,now()),NULLIF($10,'')::timestamptz,$11::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,acknowledged_by=EXCLUDED.acknowledged_by,acknowledged_at=EXCLUDED.acknowledged_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.incidentId || null, item.agentId || null, item.status || 'open', item.severity || 'medium', item.title, item.acknowledgedBy || null, item.createdAt || null, item.acknowledgedAt || '', JSON.stringify(item)]); }
async function acknowledgeAlertWithAudit(item, audit, expectedStatus = 'open') {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const current = await client.query('SELECT workspace_id,id,incident_id,agent_id,status,severity,title,acknowledged_by,created_at,acknowledged_at,payload FROM ag_alerts WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [item.workspaceId || 'default', item.id]);
    if (!current.rows[0]) return { outcome: 'not_found' };
    if (current.rows[0].status !== expectedStatus) return { outcome: 'already_acknowledged', alert: alert(current.rows[0]) };
    await client.query("UPDATE ag_alerts SET status='acknowledged',acknowledged_by=$3,acknowledged_at=$4::timestamptz,payload=$5::jsonb WHERE workspace_id=$1 AND id=$2", [item.workspaceId || 'default', item.id, item.acknowledgedBy, item.acknowledgedAt, JSON.stringify(item)]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Alert audit event ID already exists; acknowledgement was not committed'); error.statusCode = 409; throw error; }
    return { outcome: 'acknowledged', alert: item, audit: savedAudit };
  });
}
async function listAlertDeliveries(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`SELECT o.workspace_id,'outbox:'||o.alert_id AS id,o.alert_id,o.channel,
    CASE WHEN o.status='dead' THEN 'failed' WHEN o.status='delivered' THEN 'delivered' ELSE 'queued' END AS status,
    COALESCE(last.attempted_at,o.updated_at) AS attempted_at,last.delivered_at,last.http_status,
    COALESCE(o.last_error,last.error_message) AS error_message,
    jsonb_build_object('attempt',o.attempts) AS payload,o.status AS outbox_status,o.attempts AS outbox_attempts,o.available_at AS retry_at
    FROM ag_alert_outbox o LEFT JOIN LATERAL (SELECT d.attempted_at,d.delivered_at,d.http_status,d.error_message FROM ag_alert_deliveries d
      WHERE d.workspace_id=o.workspace_id AND d.alert_id=o.alert_id AND d.channel=o.channel ORDER BY d.attempted_at DESC LIMIT 1) last ON true
    WHERE o.workspace_id=$1 ORDER BY o.updated_at DESC`, [workspaceId]);
  return result.rows.map(alertDelivery);
}
async function upsertAlertDelivery(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_alert_deliveries (workspace_id,id,alert_id,channel,status,attempted_at,delivered_at,http_status,error_message,payload) VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz,now()),NULLIF($7,'')::timestamptz,$8,$9,$10::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,attempted_at=EXCLUDED.attempted_at,delivered_at=EXCLUDED.delivered_at,http_status=EXCLUDED.http_status,error_message=EXCLUDED.error_message,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.alertId, item.channel || 'webhook', item.status, item.attemptedAt || null, item.deliveredAt || '', item.httpStatus || null, item.errorMessage || null, JSON.stringify(item)]); }
async function enqueueAlertDelivery(alertItem) {
  if (!usePostgres) return undefined;
  const workspaceId = alertItem.workspaceId || 'default';
  await postgresQuery(`INSERT INTO ag_alert_outbox (workspace_id,alert_id,channel,status)
    SELECT $1,$2,'webhook','queued' WHERE EXISTS (SELECT 1 FROM ag_alerts WHERE workspace_id=$1 AND id=$2)
    ON CONFLICT (workspace_id,alert_id,channel) DO NOTHING`, [workspaceId, alertItem.id]);
  return { workspaceId, alertId: alertItem.id, channel: 'webhook', status: 'queued' };
}
async function enqueueMissingAlertDeliveries() {
  if (!usePostgres) return 0;
  const result = await postgresQuery(`INSERT INTO ag_alert_outbox (workspace_id,alert_id,channel,status)
    SELECT workspace_id,id,'webhook','queued' FROM ag_alerts WHERE status='open'
    ON CONFLICT (workspace_id,alert_id,channel) DO NOTHING`);
  return result.rowCount;
}
async function claimAlertDeliveries({ limit = 10, leaseMs = 30_000, workspaceId = null, alertId = null } = {}) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const selected = await client.query(`SELECT o.workspace_id,o.alert_id,o.channel,o.attempts,a.payload AS alert_payload
      FROM ag_alert_outbox o JOIN ag_alerts a ON a.workspace_id=o.workspace_id AND a.id=o.alert_id
      WHERE ((o.status='queued' AND o.available_at<=now()) OR (o.status='in_flight' AND o.locked_until<=now()))
        AND ($1::text IS NULL OR o.workspace_id=$1) AND ($2::text IS NULL OR o.alert_id=$2)
      ORDER BY o.available_at,o.created_at LIMIT $3 FOR UPDATE OF o SKIP LOCKED`, [workspaceId, alertId, limit]);
    const claimed = [];
    for (const row of selected.rows) {
      const updated = await client.query(`UPDATE ag_alert_outbox SET status='in_flight',attempts=attempts+1,locked_until=now()+($4::int * interval '1 millisecond'),updated_at=now()
        WHERE workspace_id=$1 AND alert_id=$2 AND channel=$3 RETURNING attempts,locked_until`, [row.workspace_id, row.alert_id, row.channel, leaseMs]);
      if (!updated.rows[0]) continue;
      claimed.push({ workspaceId: row.workspace_id, alertId: row.alert_id, channel: row.channel, attempts: updated.rows[0].attempts, lockedUntil: asIso(updated.rows[0].locked_until), alert: { ...row.alert_payload, workspaceId: row.workspace_id, id: row.alert_id } });
    }
    return claimed;
  });
}
async function finishAlertDelivery(outbox, delivery, audit, { maxAttempts = 5, retryDelayMs = null } = {}) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const retryable = delivery.status !== 'delivered' && outbox.attempts < maxAttempts;
    const delay = retryDelayMs ?? Math.min(300_000, 1000 * (2 ** Math.max(0, outbox.attempts - 1)));
    const status = delivery.status === 'delivered' ? 'delivered' : retryable ? 'queued' : 'dead';
    const updated = await client.query(`UPDATE ag_alert_outbox SET status=$4,available_at=CASE WHEN $4='queued' THEN now()+($5::int * interval '1 millisecond') ELSE available_at END,
      locked_until=NULL,last_error=$6,updated_at=now() WHERE workspace_id=$1 AND alert_id=$2 AND channel=$3 AND status='in_flight' AND attempts=$7`,
    [outbox.workspaceId, outbox.alertId, outbox.channel, status, delay, delivery.errorMessage || null, outbox.attempts]);
    if (!updated.rowCount) return { outcome: 'lease_lost' };
    await client.query(`INSERT INTO ag_alert_deliveries (workspace_id,id,alert_id,channel,status,attempted_at,delivered_at,http_status,error_message,payload)
      VALUES ($1,$2,$3,$4,$5,$6::timestamptz,NULLIF($7,'')::timestamptz,$8,$9,$10::jsonb)`,
    [delivery.workspaceId, delivery.id, delivery.alertId, delivery.channel, delivery.status, delivery.attemptedAt, delivery.deliveredAt || '', delivery.httpStatus || null, delivery.errorMessage || null, JSON.stringify({ ...delivery, attempt: outbox.attempts, retryAt: retryable ? new Date(Date.now() + delay).toISOString() : null, terminal: status === 'dead' })]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Webhook delivery audit event ID already exists; delivery result was not committed'); error.statusCode = 409; throw error; }
    return { outcome: status, delivery: { ...delivery, attempt: outbox.attempts, retryAt: retryable ? new Date(Date.now() + delay).toISOString() : null, terminal: status === 'dead' }, audit: savedAudit };
  });
}
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
async function saveAssessmentWithAudit(item, audit, expectedUpdatedAt = null) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const workspaceId = item.workspaceId || 'default';
    await client.query("SELECT pg_advisory_xact_lock(hashtext('agentguard-assessment'),hashtext($1))", [`${workspaceId}:${item.agentId}`]);
    const current = await client.query('SELECT workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload FROM ag_assessments WHERE workspace_id=$1 AND agent_id=$2 ORDER BY updated_at DESC LIMIT 1 FOR UPDATE', [workspaceId, item.agentId]);
    if (current.rows[0] && !expectedUpdatedAt) return { outcome: 'exists', assessment: assessment(current.rows[0]) };
    if (!current.rows[0] && expectedUpdatedAt) return { outcome: 'not_found' };
    if (current.rows[0] && new Date(current.rows[0].updated_at).getTime() !== new Date(expectedUpdatedAt).getTime()) return { outcome: 'stale' };
    const version = (Number(current.rows[0]?.payload?.version) || 0) + 1;
    item.version = version;
    if (current.rows[0]) {
      item.id = current.rows[0].id; item.createdAt = asIso(current.rows[0].created_at);
      await client.query(`UPDATE ag_assessments SET status=$3,owner=$4,review_due_at=NULLIF($5,'')::timestamptz,updated_at=$6::timestamptz,payload=$7::jsonb WHERE workspace_id=$1 AND id=$2`, [workspaceId, item.id, item.status || 'draft', item.owner || null, item.reviewDueAt || '', item.updatedAt, JSON.stringify(item)]);
    } else {
      await client.query(`INSERT INTO ag_assessments (workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::timestamptz,$7::timestamptz,$8::timestamptz,$9::jsonb)`, [workspaceId, item.id, item.agentId, item.status || 'draft', item.owner || null, item.reviewDueAt || '', item.createdAt, item.updatedAt, JSON.stringify(item)]);
    }
    await client.query(`INSERT INTO ag_assessment_revisions (workspace_id,assessment_id,agent_id,version,scoring_model,score,reviewer,rationale,created_at,payload)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz,$10::jsonb)`, [workspaceId,item.id,item.agentId,version,item.scoringModel,item.score,item.reviewer,item.rationale||null,item.updatedAt,JSON.stringify(item)]);
    audit.metadata = { ...(audit.metadata || {}), version, score: item.score, scoringModel: item.scoringModel };
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Assessment audit event ID already exists; assessment change was not committed'); error.statusCode = 409; throw error; }
    return { outcome: 'saved', assessment: item, audit: savedAudit };
  });
}
async function upsertPolicy(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_policies (workspace_id,id,agent_id,name,effect,enabled,version,priority,created_at,updated_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,now()),COALESCE($10::timestamptz,now()),$11::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET agent_id=EXCLUDED.agent_id,name=EXCLUDED.name,effect=EXCLUDED.effect,enabled=EXCLUDED.enabled,version=EXCLUDED.version,priority=EXCLUDED.priority,updated_at=EXCLUDED.updated_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.agentId, item.name, item.effect, Boolean(item.enabled), item.version || 1, item.priority || 100, item.createdAt || null, item.updatedAt || null, JSON.stringify(item)]); }
async function savePolicyWithAudit(item, audit, expectedVersion) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const existing = await client.query('SELECT version FROM ag_policies WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [item.workspaceId || 'default', item.id]);
    if (expectedVersion === 0 && existing.rowCount) {
      const error = new Error('Policy already exists'); error.statusCode = 409; throw error;
    }
    if (expectedVersion > 0 && !existing.rowCount) {
      const error = new Error('Policy not found'); error.statusCode = 404; throw error;
    }
    if (expectedVersion > 0 && Number(existing.rows[0].version) !== expectedVersion) {
      const error = new Error('Policy changed since it was loaded. Refresh and retry your edit.'); error.statusCode = 409; throw error;
    }
    const upsert = expectedVersion > 0 ? ` ON CONFLICT (workspace_id,id) DO UPDATE SET agent_id=EXCLUDED.agent_id,name=EXCLUDED.name,effect=EXCLUDED.effect,enabled=EXCLUDED.enabled,version=EXCLUDED.version,priority=EXCLUDED.priority,updated_at=EXCLUDED.updated_at,payload=EXCLUDED.payload` : '';
    await client.query(`INSERT INTO ag_policies (workspace_id,id,agent_id,name,effect,enabled,version,priority,created_at,updated_at,payload)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,now()),COALESCE($10::timestamptz,now()),$11::jsonb)${upsert}`,
    [item.workspaceId || 'default', item.id, item.agentId, item.name, item.effect, Boolean(item.enabled), item.version || 1, item.priority || 100, item.createdAt || null, item.updatedAt || null, JSON.stringify(item)]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) {
      const error = new Error('Audit event ID already exists; policy change was not committed'); error.statusCode = 409; throw error;
    }
    return { policy: item, audit: savedAudit };
  });
}
async function upsertApproval(item) { if (!usePostgres) return undefined; await postgresQuery(`INSERT INTO ag_approvals (workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8::timestamptz,now()),NULLIF($9,'')::timestamptz,$10::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET status=EXCLUDED.status,decided_at=EXCLUDED.decided_at,payload=EXCLUDED.payload`, [item.workspaceId || 'default', item.id, item.agentId, item.policyId || null, item.status || 'pending', item.action, item.actionRef || null, item.createdAt || null, item.decidedAt || '', JSON.stringify(item)]); }
async function createApprovalWithAudit(item, audit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const result = await client.query(`INSERT INTO ag_approvals (workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload)
      VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8::timestamptz,now()),NULL,$9::jsonb)
      RETURNING workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload`,
    [item.workspaceId || 'default', item.id, item.agentId, item.policyId || null, item.status || 'pending', item.action, item.actionRef || null, item.createdAt || null, JSON.stringify(item)]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Approval audit event ID already exists; approval was not created'); error.statusCode = 409; throw error; }
    const created = approval(result.rows[0]);
    const notification = await insertApprovalNotification(client, created);
    return { approval: created, audit: savedAudit, alert: notification };
  });
}
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

// Reviewer decision, governed-action state transition, and the corresponding
// hash-chained audit record share one transaction. Expiry wins if the deadline
// has passed by the time the row lock is acquired.
async function decideApprovalWithAudit(id, workspaceId, decision) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const locked = await client.query('SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload FROM ag_approvals WHERE id=$1 AND workspace_id=$2 FOR UPDATE', [id, workspaceId]);
    if (!locked.rows[0]) return { outcome: 'not_found' };
    const current = approval(locked.rows[0]);
    if (current.status !== 'pending') return { outcome: 'already_decided', approval: current };
    const now = new Date().toISOString();
    const expired = current.expiresAt && new Date(current.expiresAt).getTime() <= Date.now();
    const { agentName, ...decisionFields } = decision;
    const update = expired
      ? { ...current, status: 'denied', decision: 'expired', decidedAt: now, decidedBy: 'system', rationale: 'Approval expired before a reviewer decided.' }
      : { ...current, ...decisionFields, decidedAt: now };
    const saved = await client.query(`UPDATE ag_approvals SET status=$3,decided_at=$4::timestamptz,payload=$5::jsonb
      WHERE workspace_id=$1 AND id=$2 AND status='pending'
      RETURNING workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload`, [workspaceId, id, update.status, now, JSON.stringify(update)]);
    if (!saved.rows[0]) return { outcome: 'already_decided' };
    const savedApproval = approval(saved.rows[0]);
    const state = expired ? 'expired' : update.status === 'approved' ? 'approved' : 'denied';
    if (state !== 'approved') await client.query(`UPDATE ag_budget_reservations SET released_at=$5::timestamptz WHERE workspace_id=$1 AND policy_id=$2 AND agent_id=$3 AND action_ref=$4 AND released_at IS NULL`, [workspaceId, current.policyId, current.agentId, current.actionRef, now]);
    await client.query(`UPDATE ag_governed_actions SET state=$3,updated_at=$4::timestamptz,payload=payload || $5::jsonb
      WHERE workspace_id=$1 AND approval_id=$2 AND state='awaiting_approval'`, [workspaceId, id, state, now, JSON.stringify({ state, ...(expired ? { expiredAt: now } : { decidedAt: now }) })]);
    const actionVerb = expired ? 'expired' : update.status === 'approved' ? 'approved' : 'denied';
    const message = expired
      ? `Approval expired: ${current.action}`
      : `${agentName || current.agentId} was ${actionVerb} ${update.status === 'approved' ? 'to' : 'permission to'} ${current.action.toLowerCase()}.${update.rationale ? ' Note: ' + update.rationale : ''}`;
    const item = { id: require('node:crypto').randomUUID(), workspaceId, agentId: current.agentId, kind: expired || update.status === 'denied' ? 'block' : 'action', eventType: expired ? 'approval.expired' : update.status === 'approved' ? 'approval.approved' : 'approval.denied', actor: expired ? 'system' : update.decidedBy || 'workspace-user', message, action: current.action, actionType: current.actionType || null, resource: current.resource || null, actionRef: current.actionRef, approvalId: current.id, policyId: current.policyId, decidedBy: update.decidedBy || 'system', rationale: update.rationale || null, createdAt: now };
    if (!expired && update.status === 'approved') {
      const audit = await appendEventWithClient(client, item);
      return { outcome: 'decided', approval: savedApproval, audit };
    }
    const signals = await insertGovernanceSignal(client, item, 'medium');
    return { outcome: expired ? 'expired' : 'decided', approval: savedApproval, ...signals };
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
      await client.query(`UPDATE ag_budget_reservations SET released_at=$5::timestamptz WHERE workspace_id=$1 AND policy_id=$2 AND agent_id=$3 AND action_ref=$4 AND released_at IS NULL`, [row.workspace_id, row.policy_id, row.agent_id, row.action_ref, decidedAt]);
      await client.query(`UPDATE ag_governed_actions SET state='expired',updated_at=$3::timestamptz,payload=payload || $4::jsonb
        WHERE workspace_id=$1 AND approval_id=$2 AND state IN ('awaiting_approval','approved')`, [row.workspace_id, row.id, decidedAt, JSON.stringify({ state: 'expired', expiredAt: decidedAt })]);
      const eventId = require('node:crypto').randomUUID();
      const message = `Approval expired: ${row.action}`;
      await appendEventWithClient(client, { id: eventId, workspaceId: row.workspace_id, agentId: row.agent_id, kind: 'block', eventType: 'approval.expired', actor: 'system', message, action: row.action, actionType: current.actionType || null, resource: current.resource || null, approvalId: row.id, actionRef: row.action_ref, policyId: row.policy_id, createdAt: decidedAt });
      const incidentId = require('node:crypto').randomUUID();
      const incident = { id: incidentId, workspaceId: row.workspace_id, agentId: row.agent_id, status: 'open', severity: 'medium', title: message, sourceEventId: eventId, createdAt: decidedAt, updatedAt: decidedAt, timeline: [{ at: decidedAt, actor: 'system', note: 'Approval expired without reviewer action; follow-up required.' }] };
      await client.query(`INSERT INTO ag_incidents (workspace_id,id,agent_id,status,severity,title,source_event_id,created_at,updated_at,payload) VALUES ($1,$2,$3,'open','medium',$4,$5,$6::timestamptz,$6::timestamptz,$7::jsonb)`, [row.workspace_id, incident.id, row.agent_id, incident.title, eventId, decidedAt, JSON.stringify(incident)]);
      const alert = { id: require('node:crypto').randomUUID(), workspaceId: row.workspace_id, incidentId, agentId: row.agent_id, status: 'open', severity: 'medium', title: `Approval expired: ${row.action}`, createdAt: decidedAt, channels: ['in-app'] };
      Object.assign(alert, { channels: ['in-app', 'webhook'], notificationType: 'approval.expired', approvalId: row.id, action: row.action, actionType: current.actionType || null, resource: current.resource || null });
      await client.query(`INSERT INTO ag_alerts (workspace_id,id,incident_id,agent_id,status,severity,title,created_at,payload) VALUES ($1,$2,$3,$4,'open','medium',$5,$6::timestamptz,$7::jsonb)`, [row.workspace_id, alert.id, incidentId, row.agent_id, alert.title, decidedAt, JSON.stringify(alert)]);
      await client.query(`INSERT INTO ag_alert_outbox (workspace_id,alert_id,channel,status) VALUES ($1,$2,'webhook','queued') ON CONFLICT (workspace_id,alert_id,channel) DO NOTHING`, [row.workspace_id, alert.id]);
      expired.push({ ...approval(changed.rows[0]), incident, alert });
    }
    return expired;
  });
}
async function createDueAssessmentReviewAlerts(limit = 100) {
  if (!usePostgres) return [];
  return postgresTransaction(async client => {
    const due = await client.query(`SELECT workspace_id,id,agent_id,status,owner,review_due_at,payload FROM ag_assessments a
      WHERE review_due_at IS NOT NULL AND review_due_at<=now() AND status='approved'
        AND NOT EXISTS (SELECT 1 FROM ag_alerts x WHERE x.workspace_id=a.workspace_id
          AND x.payload->>'notificationType'='assessment.review_due' AND x.payload->>'assessmentId'=a.id
          AND COALESCE((x.payload->>'assessmentVersion')::int,0)=COALESCE((a.payload->>'version')::int,0))
      ORDER BY review_due_at LIMIT $1 FOR UPDATE OF a SKIP LOCKED`, [limit]);
    const created = [];
    for (const row of due.rows) {
      const now = new Date().toISOString(); const current = assessment(row);
      const title = `Risk assessment review overdue: ${row.agent_id}`;
      const auditId = require('node:crypto').randomUUID();
      const audit = await appendEventWithClient(client, { id: auditId, workspaceId: row.workspace_id, agentId: row.agent_id, kind: 'block', eventType: 'assessment.review_due', actor: 'system', message: title, assessmentId: row.id, assessmentVersion: current.version, reviewDueAt: current.reviewDueAt, createdAt: now });
      const incident = { id: require('node:crypto').randomUUID(), workspaceId: row.workspace_id, agentId: row.agent_id, status: 'open', severity: current.score >= 70 ? 'high' : 'medium', title, sourceEventId: auditId, createdAt: now, updatedAt: now, timeline: [{ at: now, actor: 'system', note: `Assessment version ${current.version} passed its review date.` }] };
      await client.query(`INSERT INTO ag_incidents (workspace_id,id,agent_id,status,severity,title,owner,source_event_id,created_at,updated_at,payload) VALUES ($1,$2,$3,'open',$4,$5,$6,$7,$8::timestamptz,$8::timestamptz,$9::jsonb)`, [row.workspace_id,incident.id,row.agent_id,incident.severity,title,row.owner||null,auditId,now,JSON.stringify(incident)]);
      const alert = { id: require('node:crypto').randomUUID(), workspaceId: row.workspace_id, incidentId: incident.id, agentId: row.agent_id, status: 'open', severity: incident.severity, title, createdAt: now, channels: ['in-app','webhook'], notificationType: 'assessment.review_due', assessmentId: row.id, assessmentVersion: current.version, reviewDueAt: current.reviewDueAt };
      await client.query(`INSERT INTO ag_alerts (workspace_id,id,incident_id,agent_id,status,severity,title,created_at,payload) VALUES ($1,$2,$3,$4,'open',$5,$6,$7::timestamptz,$8::jsonb)`, [row.workspace_id,alert.id,incident.id,row.agent_id,alert.severity,title,now,JSON.stringify(alert)]);
      await client.query(`INSERT INTO ag_alert_outbox (workspace_id,alert_id,channel,status) VALUES ($1,$2,'webhook','queued') ON CONFLICT DO NOTHING`, [row.workspace_id,alert.id]);
      created.push({ assessment: current, audit, incident, alert });
    }
    return created;
  });
}
async function createUpcomingAssessmentReviewAlerts(days = 7, limit = 100) {
  if (!usePostgres) return [];
  const reminderDays = Math.max(1, Math.min(90, Number(days) || 7));
  return postgresTransaction(async client => {
    const upcoming = await client.query(`SELECT workspace_id,id,agent_id,status,owner,review_due_at,payload FROM ag_assessments a
      WHERE review_due_at>now() AND review_due_at<=now()+($1::int * interval '1 day') AND status='approved'
        AND NOT EXISTS (SELECT 1 FROM ag_alerts x WHERE x.workspace_id=a.workspace_id
          AND x.payload->>'notificationType'='assessment.review_upcoming' AND x.payload->>'assessmentId'=a.id
          AND COALESCE((x.payload->>'assessmentVersion')::int,0)=COALESCE((a.payload->>'version')::int,0))
      ORDER BY review_due_at LIMIT $2 FOR UPDATE OF a SKIP LOCKED`, [reminderDays,limit]);
    const created = [];
    for (const row of upcoming.rows) {
      const now = new Date().toISOString(); const current = assessment(row);
      const title = `Risk assessment review due soon: ${row.agent_id}`;
      const audit = await appendEventWithClient(client, { id: require('node:crypto').randomUUID(), workspaceId: row.workspace_id, agentId: row.agent_id, kind: 'action', eventType: 'assessment.review_upcoming', actor: 'system', message: title, assessmentId: row.id, assessmentVersion: current.version, reviewDueAt: current.reviewDueAt, createdAt: now });
      const alert = { id: require('node:crypto').randomUUID(), workspaceId: row.workspace_id, incidentId: null, agentId: row.agent_id, status: 'open', severity: 'low', title, createdAt: now, channels: ['in-app','webhook'], notificationType: 'assessment.review_upcoming', assessmentId: row.id, assessmentVersion: current.version, reviewDueAt: current.reviewDueAt };
      await client.query(`INSERT INTO ag_alerts (workspace_id,id,incident_id,agent_id,status,severity,title,created_at,payload) VALUES ($1,$2,NULL,$3,'open','low',$4,$5::timestamptz,$6::jsonb)`, [row.workspace_id,alert.id,row.agent_id,title,now,JSON.stringify(alert)]);
      await client.query(`INSERT INTO ag_alert_outbox (workspace_id,alert_id,channel,status) VALUES ($1,$2,'webhook','queued') ON CONFLICT DO NOTHING`, [row.workspace_id,alert.id]);
      created.push({ assessment: current, audit, alert });
    }
    return created;
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

module.exports = { listPolicies, getPolicy, findApprovalForAction, decideApproval, decideApprovalWithAudit, checkGovernedAction, expireDueApprovals, createDueAssessmentReviewAlerts, createUpcomingAssessmentReviewAlerts, listApprovals, getApproval, createApprovalWithAudit, listEvents, listAssessments, getAssessment, listAssessmentRevisions, listIncidents, upsertIncident, saveIncidentWithAudit, listAlerts, upsertAlert, acknowledgeAlertWithAudit, listAlertDeliveries, upsertAlertDelivery, enqueueAlertDelivery, enqueueMissingAlertDeliveries, claimAlertDeliveries, finishAlertDelivery, exportEvidence, upsertAssessment, saveAssessmentWithAudit, upsertPolicy, savePolicyWithAudit, upsertApproval, upsertGovernedAction, claimGovernedAction, completeGovernedAction, listUncertainGovernedActions, reconcileGovernedAction, recordGovernanceSignal, appendEvent, appendEventWithClient, flushAudit };
