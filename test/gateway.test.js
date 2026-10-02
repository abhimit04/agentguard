const test = require('node:test');
const assert = require('node:assert/strict');
const { issueToken, tokenMatches, normalizeEnvelope, applyEnvelope, expireHeartbeats, expireRuntimeActivity } = require('../gateway');

test('agent credentials are scoped and verifiable without storing the secret', () => {
  const credential = issueToken();
  assert.match(credential.token, /^ag_live_/);
  assert.equal(tokenMatches(credential.token, credential.hash), true);
  assert.equal(tokenMatches('wrong', credential.hash), false);
});

test('standard telemetry updates registry status, task, latency, and token usage', () => {
  const store = { agents: [{ id: 'agent-1', companyId: 'company-a', status: 'registered', runtimeStatus: 'offline' }], events: [] };
  const envelope = normalizeEnvelope({ companyId: 'company-a', agentId: 'agent-1', eventType: 'task.started', status: 'running', task: { id: 'task-1', name: 'Review PR-123' }, metrics: { latencyMs: 42, inputTokens: 1200, outputTokens: 450, llmCalls: 1 } });
  applyEnvelope(store, envelope, (target, kind, message, metadata) => target.events.unshift({ kind, message, ...metadata }));
  assert.equal(store.agents[0].runtimeStatus, 'running');
  assert.equal(store.agents[0].currentTask.name, 'Review PR-123');
  assert.equal(store.agents[0].usage.inputTokens, 1200);
  assert.equal(store.agents[0].lastLatencyMs, 42);
});
// test
test('expired gateway heartbeats mark only stale agents offline', () => {
  const store = { agents: [
    { id: 'stale', connection: { mode: 'gateway', desiredState: 'running' }, lastSeenAt: '2026-01-01T00:00:00Z', runtimeStatus: 'running', status: 'healthy' },
    { id: 'fresh', connection: { mode: 'gateway', desiredState: 'running' }, lastSeenAt: '2026-09-27T00:00:00Z', runtimeStatus: 'running', status: 'healthy' }
  ] };
  assert.equal(expireHeartbeats(store, 60_000, new Date('2026-09-27T00:00:30Z').getTime()), 1);
  assert.equal(store.agents[0].runtimeStatus, 'offline');
  assert.equal(store.agents[1].runtimeStatus, 'running');
});

test('running agents become idle after the activity timeout while remaining connected', () => {
  const store = { agents: [{ id: 'idle-agent', status: 'healthy', runtimeStatus: 'running', lastActivityAt: '2026-09-27T00:00:00Z', connection: { mode: 'gateway', desiredState: 'running' }, currentTask: { id: 'task-1' } }] };
  assert.equal(expireRuntimeActivity(store, 60_000, new Date('2026-09-27T00:02:00Z').getTime()), 1);
  assert.equal(store.agents[0].runtimeStatus, 'idle');
  assert.equal(store.agents[0].status, 'healthy');
  assert.equal(store.agents[0].currentTask, null);
});

test('heartbeats preserve running state and establish idle state after first connection', () => {
  assert.equal(require('../gateway').deriveStatus({ eventType: 'heartbeat', status: null }, 'running'), 'running');
  assert.equal(require('../gateway').deriveStatus({ eventType: 'heartbeat', status: null }, 'offline'), 'idle');
});

test('heartbeats update liveness without creating audit activity', () => {
  const store = { agents: [{ id: 'agent-1', companyId: 'company-a', status: 'registered', runtimeStatus: 'offline' }], events: [] };
  const envelope = normalizeEnvelope({ companyId: 'company-a', agentId: 'agent-1', eventType: 'heartbeat', message: 'Agent is online' });
  applyEnvelope(store, envelope, (target, kind, message, metadata) => target.events.unshift({ kind, message, ...metadata }));
  assert.equal(store.agents[0].status, 'healthy');
  assert.equal(store.agents[0].runtimeStatus, 'idle');
  assert.equal(store.agents[0].usage.events, 0);
  assert.equal(store.events.length, 0);
});

test('a failed heartbeat overrides a stale running state', () => {
  const store = { agents: [{ id: '1001', companyId: 'acme', status: 'healthy', runtimeStatus: 'running' }], events: [] };
  const envelope = normalizeEnvelope({ companyId: 'acme', agentId: '1001', eventType: 'heartbeat', status: 'failed', error: 'runtime unavailable' });
  applyEnvelope(store, envelope, () => {});
  assert.equal(store.agents[0].runtimeStatus, 'failed');
});
//test it
