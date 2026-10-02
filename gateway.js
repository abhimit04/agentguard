const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');

const STATUSES = new Set(['running', 'idle', 'waiting', 'failed', 'offline']);

function tokenHash(token) { return createHash('sha256').update(String(token)).digest('hex'); }
function issueToken() { const token = `ag_live_${randomBytes(24).toString('base64url')}`; return { token, hash: tokenHash(token) }; }
function tokenMatches(token, hash) {
  if (!token || !hash) return false;
  const actual = Buffer.from(tokenHash(token));
  const expected = Buffer.from(String(hash));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function normalizeEnvelope(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Telemetry event must be an object');
  const eventType = String(input.eventType || input.event || '').trim();
  if (!input.companyId || !input.agentId || !eventType) throw new Error('companyId, agentId, and eventType are required');
  const metrics = input.metrics && typeof input.metrics === 'object' ? input.metrics : {};
  return {
    eventId: String(input.eventId || '').slice(0, 128) || null,
    companyId: String(input.companyId).slice(0, 128),
    agentId: String(input.agentId).slice(0, 128),
    eventType: eventType.slice(0, 128),
    status: input.status === 'waiting' ? 'idle' : STATUSES.has(input.status) ? input.status : null,
    timestamp: input.timestamp || new Date().toISOString(),
    message: String(input.message || eventType).slice(0, 2000),
    task: input.task && typeof input.task === 'object' ? { id: String(input.task.id || '').slice(0, 128) || null, name: String(input.task.name || '').slice(0, 500) || null } : null,
    error: input.error ? String(typeof input.error === 'object' ? input.error.message || JSON.stringify(input.error) : input.error).slice(0, 2000) : null,
    traceId: input.traceId ? String(input.traceId).slice(0, 128) : null,
    spanId: input.spanId ? String(input.spanId).slice(0, 128) : null,
    actionRef: input.actionRef ? String(input.actionRef).slice(0, 256) : null,
    runId: input.runId ? String(input.runId).slice(0, 256) : null,
    tool: input.tool ? String(input.tool).slice(0, 256) : null,
    metrics: {
      latencyMs: Number.isFinite(Number(metrics.latencyMs)) ? Math.max(0, Number(metrics.latencyMs)) : null,
      inputTokens: Number.isFinite(Number(metrics.inputTokens)) ? Math.max(0, Number(metrics.inputTokens)) : 0,
      outputTokens: Number.isFinite(Number(metrics.outputTokens)) ? Math.max(0, Number(metrics.outputTokens)) : 0,
      llmCalls: Number.isFinite(Number(metrics.llmCalls)) ? Math.max(0, Number(metrics.llmCalls)) : 0,
      costUsd: Number.isFinite(Number(metrics.costUsd)) ? Math.max(0, Number(metrics.costUsd)) : null
    },
    metadata: input.metadata && typeof input.metadata === 'object' ? input.metadata : null
  };
}

function deriveStatus(envelope, current = 'waiting') {
  if (envelope.error || envelope.eventType === 'failed' || envelope.eventType.endsWith('.failed')) return 'failed';
  if (envelope.status) return envelope.status;
  if (envelope.eventType === 'heartbeat') return current === 'offline' ? 'idle' : current;
  if (['task.started', 'agent.started', 'started', 'running'].includes(envelope.eventType)) return 'running';
  if (['task.waiting', 'task.completed', 'agent.completed', 'completed', 'idle', 'waiting'].includes(envelope.eventType)) return 'idle';
  return current;
}

function applyEnvelope(store, envelope, addEvent) {
  if (envelope.eventId && store.events.some(item => item.eventId === envelope.eventId && item.companyId === envelope.companyId)) return { duplicate: true, agent: store.agents.find(item => item.id === envelope.agentId && item.companyId === envelope.companyId) };
  const agent = store.agents.find(item => item.id === envelope.agentId && item.companyId === envelope.companyId);
  if (!agent) throw Object.assign(new Error('Agent is not registered for this company'), { statusCode: 404 });
  if (agent.archived) throw Object.assign(new Error('Agent is archived'), { statusCode: 409 });
  const now = new Date().toISOString();
  agent.status = 'healthy';
  agent.runtimeStatus = deriveStatus(envelope, agent.runtimeStatus || 'waiting');
  agent.lastSeenAt = now;
  if (agent.runtimeStatus === 'running' && envelope.eventType !== 'heartbeat') agent.lastActivityAt = now;
  if (['task.completed', 'task.waiting', 'agent.completed', 'completed', 'idle', 'waiting'].includes(envelope.eventType)) {
    agent.runtimeStatus = 'running';
    agent.currentTask = null;
    agent.lastActivityAt = now;
    agent.idleAfterAt = new Date(Date.now() + Number(process.env.AGENTGUARD_COMPLETION_GRACE_MS || 120000)).toISOString();
  }
  agent.connection = { ...(agent.connection || {}), mode: 'gateway', state: 'connected', desiredState: 'running', lastError: null, lastCheckedAt: now };
  if (envelope.task) agent.currentTask = envelope.eventType === 'task.completed' ? null : envelope.task;
  agent.usage = agent.usage || { inputTokens: 0, outputTokens: 0, llmCalls: 0, costUsd: 0, events: 0 };
  agent.usage.inputTokens += envelope.metrics.inputTokens;
  agent.usage.outputTokens += envelope.metrics.outputTokens;
  agent.usage.llmCalls += envelope.metrics.llmCalls;
  agent.usage.costUsd += envelope.metrics.costUsd || 0;
  if (envelope.eventType !== 'heartbeat') agent.usage.events += 1;
  agent.lastLatencyMs = envelope.metrics.latencyMs;
  if (envelope.eventType !== 'heartbeat') {
    const kind = agent.runtimeStatus === 'failed' ? 'block' : envelope.eventType.includes('approval') ? 'approval' : 'action';
    addEvent(store, kind, envelope.error ? `${envelope.message}: ${envelope.error}` : envelope.message, { ...envelope, actor: `agent:${agent.id}` });
  }
  return { duplicate: false, agent };
}

function expireRuntimeActivity(store, timeoutMs = 60_000, now = Date.now()) {
  let changed = 0;
  for (const agent of store.agents) {
    if (agent.archived || agent.status !== 'healthy' || agent.runtimeStatus !== 'running') continue;
    const lastActivity = new Date(agent.lastActivityAt || agent.lastSeenAt || 0).getTime();
    const idleAfter = new Date(agent.idleAfterAt || 0).getTime();
    if (idleAfter && now < idleAfter) continue;
    if (!lastActivity || now - lastActivity <= timeoutMs) continue;
    agent.runtimeStatus = 'idle';
    agent.idleAfterAt = null;
    agent.currentTask = null;
    changed++;
  }
  return changed;
}

function expireHeartbeats(store, timeoutMs = 60_000, now = Date.now()) {
  let changed = 0;
  for (const agent of store.agents) {
    if (agent.archived || agent.connection?.mode !== 'gateway' || agent.connection?.desiredState !== 'running' || !agent.lastSeenAt) continue;
    if (now - new Date(agent.lastSeenAt).getTime() <= timeoutMs || agent.runtimeStatus === 'offline') continue;
    agent.status = 'registered';
    agent.runtimeStatus = 'offline';
    agent.currentTask = null;
    agent.connection = { ...agent.connection, state: 'offline', lastError: 'Heartbeat expired' };
    changed++;
  }
  return changed;
}

module.exports = { issueToken, tokenHash, tokenMatches, normalizeEnvelope, deriveStatus, applyEnvelope, expireHeartbeats, expireRuntimeActivity };
