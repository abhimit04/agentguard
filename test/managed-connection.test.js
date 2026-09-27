const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { normalizedRuntimeUrl, probeManagedAgent, runtimeUrlOwner } = require('../server');

test('managed connector validates runtime URLs', () => {
  assert.equal(normalizedRuntimeUrl('http://localhost:3000/health/'), 'http://localhost:3000/health');
  assert.throws(() => normalizedRuntimeUrl('file:///etc/passwd'), /http or https/);
  assert.throws(() => normalizedRuntimeUrl('http://169.254.169.254/latest/meta-data'), /not allowed/);
});

test('managed connector verifies a live agent and captures its JSON snapshot', async () => {
  const runtime = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, agentId: '5497', status: 'ready', activeRuns: 2 }));
  });
  await new Promise(resolve => runtime.listen(0, '127.0.0.1', resolve));
  try {
    const snapshot = await probeManagedAgent({ id: '5497', name: 'Stock Agent', connection: { runtimeUrl: `http://127.0.0.1:${runtime.address().port}/status` } });
    assert.deepEqual(snapshot, { ok: true, agentId: '5497', status: 'ready', activeRuns: 2 });
  } finally { await new Promise(resolve => runtime.close(resolve)); }
});

test('one API URL can be actively bound to only one registered agent', () => {
  const store = { agents: [{ id: '5497', name: 'Stock Agent', connection: { runtimeUrl: 'http://localhost:8000/api/status', desiredState: 'running' } }] };
  assert.equal(runtimeUrlOwner(store, 'http://localhost:8000/api/status', '5760').id, '5497');
  assert.equal(runtimeUrlOwner(store, 'http://localhost:9000/api/status', '5760'), null);
});
