const { randomUUID } = require('node:crypto');
const { postgresTransaction, postgresQuery } = require('../storage');
const { applyEnvelope, tokenMatches, expireHeartbeats, expireRuntimeActivity } = require('../gateway');
const { appendEventWithClient } = require('./governance');

function failure(statusCode, message) { return Object.assign(new Error(message), { statusCode }); }

async function loadAgent(client, identity, lock = false) {
  const result = await client.query(`SELECT a.*, c.gateway_credential_hash AS company_credential_hash
    FROM ag_agents a JOIN ag_companies c ON c.workspace_id=a.workspace_id AND c.id=a.company_id
    WHERE a.id=$1 AND ($2::text IS NULL OR a.company_id=$2)
      AND ($3::text IS NULL OR a.workspace_id=$3)
    ORDER BY a.workspace_id ${lock ? 'FOR UPDATE OF a FOR SHARE OF c' : ''}`,
  [identity.agentId, identity.companyId || null, identity.workspaceId || null]);
  if (result.rows.length !== 1) throw failure(result.rows.length ? 409 : 404, 'Agent identity is unknown or ambiguous; specify workspace, company and agent');
  const row = result.rows[0];
  return { row, agent: { ...row.payload, id: row.id, workspaceId: row.workspace_id, companyId: row.company_id,
    credentialHash: row.credential_hash, status: row.status, runtimeStatus: row.runtime_status,
    lastSeenAt: row.last_seen_at?.toISOString() || null } };
}

function authorize(row, credential) {
  if (credential?.integration === true) return;
  if (tokenMatches(credential?.token, row.credential_hash)) return;
  if (credential?.company === true && tokenMatches(credential.token, row.company_credential_hash)) return;
  throw failure(401, 'Invalid company or agent credential');
}

async function readAgent(identity, credential) {
  return postgresTransaction(async client => {
    const { row, agent } = await loadAgent(client, identity);
    authorize(row, credential);
    return agent;
  });
}

async function saveAgent(client, agent) {
  await client.query(`UPDATE ag_agents SET status=$3,runtime_status=$4,last_seen_at=$5::timestamptz,
    updated_at=now(),payload=$6::jsonb WHERE workspace_id=$1 AND id=$2`,
  [agent.workspaceId, agent.id, agent.status, agent.runtimeStatus, agent.lastSeenAt || null, JSON.stringify(agent)]);
}

async function record(client, agent, pending, result) {
  for (const item of pending) {
    const audit = { ...item.metadata, id: randomUUID(), workspaceId: agent.workspaceId,
      companyId: agent.companyId, agentId: agent.id, kind: item.kind, message: item.message,
      actor: item.metadata.actor || `agent:${agent.id}`, createdAt: new Date().toISOString() };
    await appendEventWithClient(client, audit);
    result.events.push(audit);
    if (audit.kind !== 'block' || !(['failed', 'connector.failed', 'policy.blocked'].includes(audit.eventType) || audit.eventType.endsWith('.failed'))) continue;
    const incident = { id: randomUUID(), workspaceId: agent.workspaceId, agentId: agent.id, status: 'open',
      severity: audit.eventType === 'connector.failed' ? 'high' : 'medium', title: audit.message.slice(0, 240),
      sourceEventId: audit.id, createdAt: audit.createdAt, updatedAt: audit.createdAt,
      timeline: [{ at: audit.createdAt, actor: audit.actor, note: 'Incident opened from telemetry.' }] };
    const alert = { id: randomUUID(), workspaceId: agent.workspaceId, agentId: agent.id, incidentId: incident.id,
      status: 'open', severity: incident.severity, title: incident.title, channels: ['in-app'], createdAt: audit.createdAt };
    await client.query(`INSERT INTO ag_incidents(workspace_id,id,agent_id,status,severity,title,source_event_id,payload)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, [agent.workspaceId, incident.id, agent.id, incident.status, incident.severity, incident.title, audit.id, JSON.stringify(incident)]);
    await client.query(`INSERT INTO ag_alerts(workspace_id,id,incident_id,agent_id,status,severity,title,payload)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, [agent.workspaceId, alert.id, incident.id, agent.id, alert.status, alert.severity, alert.title, JSON.stringify(alert)]);
    result.incidents.push(incident); result.alerts.push(alert);
  }
}

// A callback mutates only a transaction-local agent. Cache publication belongs
// to the caller after COMMIT, so rollback cannot make a failed event visible.
async function updateRuntime(identity, update) {
  return postgresTransaction(async client => {
    const { agent } = await loadAgent(client, identity, true);
    const result = { agent, events: [], incidents: [], alerts: [] };
    const pending = [];
    const changed = await update(agent, (kind, message, metadata = {}) => pending.push({ kind, message, metadata }));
    if (changed === false) return result;
    await saveAgent(client, agent);
    await record(client, agent, pending, result);
    return result;
  });
}

async function ingest(identity, envelopes, credential) {
  return postgresTransaction(async client => {
    const { row, agent } = await loadAgent(client, identity, true);
    authorize(row, credential);
    if (agent.archived) throw failure(409, 'Agent is archived');
    const result = { agent, accepted: 0, duplicates: 0, events: [], incidents: [], alerts: [] };
    const pending = [];
    for (const envelope of envelopes) {
      if (envelope.agentId !== agent.id || envelope.companyId !== agent.companyId) throw failure(403, 'Telemetry identity does not match authenticated agent');
      if (envelope.eventId) {
        const receipt = await client.query(`INSERT INTO ag_telemetry_receipts(workspace_id,company_id,agent_id,event_id)
          VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING event_id`, [agent.workspaceId, agent.companyId, agent.id, envelope.eventId]);
        if (!receipt.rowCount) { result.duplicates++; continue; }
      }
      applyEnvelope({ agents: [agent], events: [] }, envelope, (_store, kind, message, metadata) => pending.push({ kind, message, metadata }));
      result.accepted++;
    }
    if (result.accepted) {
      await saveAgent(client, agent);
      await record(client, agent, pending, result);
    }
    return result;
  });
}

async function expireStates(heartbeatMs, idleMs, now = Date.now()) {
  const candidates = await postgresQuery("SELECT workspace_id,company_id,id FROM ag_agents WHERE status='healthy'");
  const results = [];
  for (const row of candidates.rows) {
    const result = await updateRuntime({ workspaceId: row.workspace_id, companyId: row.company_id, agentId: row.id }, agent => {
      const local = { agents: [agent] };
      return Boolean(expireHeartbeats(local, heartbeatMs, now) + expireRuntimeActivity(local, idleMs, now));
    });
    results.push(result);
  }
  return results;
}

module.exports = { ingest, readAgent, updateRuntime, expireStates };
