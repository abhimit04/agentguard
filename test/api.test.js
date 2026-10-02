process.env.AGENTGUARD_STORAGE = 'sqlite';
process.env.DATABASE_URL = '';
process.env.AGENTGUARD_REQUIRE_AUTH = 'false';
process.env.AGENTGUARD_RATE_LIMIT = '2';
process.env.AGENTGUARD_API_KEY = 'test-rate-limit-key';
const test = require('node:test');
const assert = require('node:assert/strict');
const { server, acquireTelemetrySlot } = require('../server');
const { readStore, writeStore } = require('../storage');
const { issueToken } = require('../gateway');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { listBackupArtifacts, backupHealth } = require('../server');

let baseUrl;
test.before(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});
test.after(() => server.close());

test('health endpoint reports ready', async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
  assert.match(response.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.match(response.headers.get('permissions-policy'), /camera=\(\)/);
});

test('operations health exposes telemetry admission capacity', async () => {
  const response = await fetch(`${baseUrl}/api/operations/health`);
  const health = await response.json();
  assert.equal(response.status, 200);
  assert.equal(health.rateLimiting.inFlight, 0);
  assert.equal(health.rateLimiting.inFlightLimit, 50);
  assert.equal(health.rateLimiting.overloadRejections, 0);
  assert.equal(health.rateLimiting.committed, 0);
  assert.equal(health.rateLimiting.commitFailures, 0);
  assert.equal(health.rateLimiting.averageCommitMs, 0);
});

test('backup discovery includes scheduled PostgreSQL dumps in nested folders', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-backups-'));
  try {
    fs.mkdirSync(path.join(root, 'daily'));
    fs.writeFileSync(path.join(root, 'daily', 'agentguard.sql.gz'), 'dump');
    fs.writeFileSync(path.join(root, 'legacy.json'), '{}');
    fs.writeFileSync(path.join(root, 'daily', 'agentguard.sql.gz.manifest.json'), '{}');
    const backups = listBackupArtifacts(root);
    assert.deepEqual(backups.map(item => [item.name, item.format]).sort(), [['daily/agentguard.sql.gz', 'postgres-sql-gzip'], ['legacy.json', 'json-snapshot']]);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('backup health distinguishes fresh, overdue, and missing backups', () => {
  const now = Date.parse('2026-10-01T12:00:00.000Z');
  assert.equal(backupHealth(null, 26, now).status, 'missing');
  assert.equal(backupHealth({ modifiedAt: '2026-10-01T02:00:00.000Z', format: 'postgres-sql-gzip' }, 26, now).status, 'healthy');
  assert.equal(backupHealth({ modifiedAt: '2026-09-29T12:00:00.000Z', format: 'postgres-sql-gzip' }, 26, now).status, 'overdue');
});

test('oversized JSON is rejected before policy processing', async () => {
  const original = process.env.AGENTGUARD_MAX_BODY_BYTES;
  process.env.AGENTGUARD_MAX_BODY_BYTES = '16384';
  try {
    const response = await fetch(`${baseUrl}/api/policies/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId: 'x', actionType: 'research', resource: 'x'.repeat(20_000) }),
    });
    assert.equal(response.status, 413);
    assert.match((await response.json()).error, /Request body exceeds/);
  } finally {
    if (original === undefined) delete process.env.AGENTGUARD_MAX_BODY_BYTES;
    else process.env.AGENTGUARD_MAX_BODY_BYTES = original;
  }
});

test('integration routes return Retry-After when the caller exceeds its rate limit', async () => {
  const agentId = `rate-limit-agent-${Date.now()}`;
  const request = () => fetch(`${baseUrl}/api/agent-events`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer test-rate-limit-key' },
    body: JSON.stringify({ agentId, eventType: 'started', message: 'Rate-limit test', agent: { name: 'Rate-limit test agent', team: 'QA', tools: [] } }),
  });
  assert.equal((await request()).status, 201);
  assert.equal((await request()).status, 201);
  const rejected = await request();
  assert.equal(rejected.status, 429);
  assert.equal(rejected.headers.get('retry-after'), '60');
});

test('gateway batches consume one rate-limit unit per telemetry envelope', async () => {
  const original = readStore();
  const store = structuredClone(original);
  const agentId = `batch-limit-agent-${Date.now()}`;
  const credential = issueToken();
  store.agents.push({ id: agentId, workspaceId: 'default', companyId: 'default', name: 'Batch limit agent', status: 'registered', runtimeStatus: 'offline', credentialHash: credential.hash, tools: [] });
  writeStore(store);
  try {
    const response = await fetch(`${baseUrl}/api/gateway/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${credential.token}`, 'x-agentguard-company': 'default', 'x-agentguard-agent': agentId },
      body: JSON.stringify([1, 2, 3].map(index => ({ eventId: `${agentId}-${index}`, companyId: 'default', agentId, eventType: 'running', message: `Batch event ${index}` }))),
    });
    assert.equal(response.status, 429);
    assert.equal(response.headers.get('retry-after'), '60');
  } finally {
    writeStore(original);
  }
});

test('local telemetry admission is bounded and releases capacity', async () => {
  const original = process.env.AGENTGUARD_MAX_INFLIGHT_TELEMETRY;
  process.env.AGENTGUARD_MAX_INFLIGHT_TELEMETRY = '1';
  const first = await acquireTelemetrySlot();
  try {
    assert.ok(first);
    assert.equal(await acquireTelemetrySlot(), null);
  } finally {
    await first?.();
    if (original === undefined) delete process.env.AGENTGUARD_MAX_INFLIGHT_TELEMETRY;
    else process.env.AGENTGUARD_MAX_INFLIGHT_TELEMETRY = original;
  }
  const afterRelease = await acquireTelemetrySlot();
  assert.ok(afterRelease);
  await afterRelease();
});

test('local telemetry admission sustains repeated load without leaking capacity', async () => {
  const original = process.env.AGENTGUARD_MAX_INFLIGHT_TELEMETRY;
  process.env.AGENTGUARD_MAX_INFLIGHT_TELEMETRY = '4';
  try {
    for (let round = 0; round < 100; round += 1) {
      const releases = await Promise.all(Array.from({ length: 4 }, () => acquireTelemetrySlot()));
      assert.equal(releases.filter(Boolean).length, 4);
      assert.equal(await acquireTelemetrySlot(), null);
      await Promise.all(releases.filter(Boolean).map(release => release()));
    }
    const recovered = await acquireTelemetrySlot();
    assert.ok(recovered);
    await recovered();
  } finally {
    if (original === undefined) delete process.env.AGENTGUARD_MAX_INFLIGHT_TELEMETRY;
    else process.env.AGENTGUARD_MAX_INFLIGHT_TELEMETRY = original;
  }
});

test('dashboard endpoint returns the core application resources', async () => {
  const response = await fetch(`${baseUrl}/api/dashboard`);
  const dashboard = await response.json();
  assert.equal(response.status, 200);
  assert.equal(dashboard.workspace.id, 'default');
  assert.ok(Array.isArray(dashboard.agents));
  assert.ok(Array.isArray(dashboard.policies));
  assert.ok(Array.isArray(dashboard.approvals));
  assert.ok(Array.isArray(dashboard.events));
});

test('evidence export produces an integrity manifest without agent credentials', async () => {
  const original = readStore();
  const store = structuredClone(original);
  const marker = `evidence-agent-${Date.now()}`;
  store.agents.push({ id: marker, workspaceId: 'default', companyId: 'default', name: 'Evidence agent', credentialHash: 'must-not-leak', connection: { mode: 'gateway', authHeader: 'must-not-leak-either' }, createdAt: new Date().toISOString() });
  writeStore(store);
  try {
    const response = await fetch(`${baseUrl}/api/evidence/export`);
    const bundle = await response.json();
    assert.equal(response.status, 200);
    assert.equal(bundle.manifest.format, 'agentguard-evidence-v1');
    assert.equal(bundle.integrity.algorithm, 'SHA-256');
    assert.match(bundle.integrity.contentSha256, /^[a-f0-9]{64}$/);
    const exported = bundle.evidence.agents.find(agent => agent.id === marker);
    assert.ok(exported);
    assert.equal(exported.credentialHash, undefined);
    assert.equal(exported.connection.authHeader, undefined);
  } finally {
    writeStore(original);
  }
});

test('editing a policy persists every editable field', async () => {
  const original = readStore();
  const store = structuredClone(original);
  const id = `policy-edit-${Date.now()}`;
  store.policies.push({ id, workspaceId: 'default', name: 'Original policy', scope: 'Original scope', agentId: '*', actionType: '*', resourcePattern: '*', effect: 'allow', priority: 10, enabled: true, version: 1, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  writeStore(store);
  try {
    const response = await fetch(`${baseUrl}/api/policies/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Updated policy', scope: 'Updated scope', agentId: '*', actionType: 'research', resourcePattern: 'ticker:*', effect: 'require_approval', priority: 200, enabled: false }) });
    const policy = await response.json();
    assert.equal(response.status, 200);
    assert.equal(policy.name, 'Updated policy');
    assert.equal(policy.actionType, 'research');
    assert.equal(policy.resourcePattern, 'ticker:*');
    assert.equal(policy.effect, 'require_approval');
    assert.equal(policy.priority, 200);
    assert.equal(policy.enabled, false);
    assert.equal(policy.version, 2);
  } finally {
    writeStore(original);
  }
});

test('dashboard does not expose records from another workspace', async () => {
  const original = readStore();
  const store = structuredClone(original);
  const marker = `isolated-${Date.now()}`;
  store.workspaces.push({ id: marker, name: 'Isolated workspace' });
  store.companies.push({ id: marker, workspaceId: marker, name: 'Hidden company' });
  store.agents.push({ id: marker, workspaceId: marker, companyId: marker, name: 'Hidden agent', status: 'registered' });
  store.events.unshift({ id: marker, workspaceId: marker, kind: 'action', message: 'Hidden event', createdAt: new Date().toISOString() });
  writeStore(store);
  try {
    const response = await fetch(`${baseUrl}/api/dashboard`);
    const dashboard = await response.json();
    assert.equal(response.status, 200);
    assert.equal(dashboard.companies.some(item => item.id === marker), false);
    assert.equal(dashboard.agents.some(item => item.id === marker), false);
    assert.equal(dashboard.events.some(item => item.id === marker), false);
  } finally {
    writeStore(original);
  }
});

test('policy simulator identifies a matching tool permission rule', async () => {
  const original = readStore();
  const store = structuredClone(original);
  const agentId = `sim-agent-${Date.now()}`;
  store.agents.push({ id: agentId, workspaceId: 'default', companyId: 'default', name: 'Simulation agent', team: 'Test', tools: ['broker-api'], status: 'registered' });
  store.policies.push({ id: `sim-policy-${Date.now()}`, workspaceId: 'default', name: 'Block broker calls', scope: 'Test', agentId, actionType: 'tool.call', resourcePattern: 'tool:broker-api', effect: 'block', enabled: true, priority: 100, version: 1 });
  writeStore(store);
  try {
    const response = await fetch(`${baseUrl}/api/policies/simulate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ agentId, actionType: 'tool.call', resource: 'tool:broker-api' }) });
    const result = await response.json();
    assert.equal(response.status, 200);
    assert.equal(result.decision, 'block');
    assert.equal(result.policy.name, 'Block broker calls');
  } finally {
    writeStore(original);
  }
});

test('coverage marks old control evidence stale instead of verified', async () => {
  const original = readStore();
  const store = structuredClone(original);
  const agentId = `coverage-agent-${Date.now()}`;
  const staleAt = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
  store.agents.push({ id: agentId, workspaceId: 'default', companyId: 'default', name: 'Coverage agent', team: 'Test', tools: [], status: 'healthy', lastSeenAt: staleAt, connection: { mode: 'gateway', desiredState: 'running' } });
  store.policies.push({ id: `coverage-policy-${Date.now()}`, workspaceId: 'default', name: 'Coverage policy', scope: 'Test', agentId, actionType: 'research', resourcePattern: '*', effect: 'require_approval', enabled: true, priority: 100, version: 1 });
  store.events.unshift({ id: `coverage-event-${Date.now()}`, workspaceId: 'default', agentId, eventType: 'policy.allowed', createdAt: staleAt, message: 'Old policy decision' });
  writeStore(store);
  try {
    const response = await fetch(`${baseUrl}/api/agents/${agentId}/coverage`);
    const result = await response.json();
    assert.equal(response.status, 200);
    assert.equal(result.coverage.healthMonitoring.status, 'stale');
    assert.equal(result.coverage.policyEnforcement.status, 'stale');
    assert.equal(result.coverage.executionTelemetry.status, 'missing');
  } finally {
    writeStore(original);
  }
});
