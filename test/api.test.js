const test = require('node:test');
const assert = require('node:assert/strict');
const { server } = require('../server');

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
});

test('dashboard endpoint returns the core application resources', async () => {
  const response = await fetch(`${baseUrl}/api/dashboard`);
  const dashboard = await response.json();
  assert.equal(response.status, 200);
  assert.ok(Array.isArray(dashboard.agents));
  assert.ok(Array.isArray(dashboard.policies));
  assert.ok(Array.isArray(dashboard.approvals));
  assert.ok(Array.isArray(dashboard.events));
});
