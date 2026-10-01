// Proves that PostgreSQL telemetry limits remain consistent across two separate
// AgentGuard processes. It creates and removes only a uniquely named scratch DB.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { spawn } = require('node:child_process');
const { Client } = require('pg');
const { tokenHash } = require('../gateway');

const schema = fs.readFileSync(path.join(__dirname, '..', 'infra', 'postgres', '002-relational.sql'), 'utf8');

function databaseUrl() {
  return process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@127.0.0.1:${process.env.POSTGRES_PORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}`;
}

async function freePort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(0, '127.0.0.1', resolve); });
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}

async function waitForHealth(baseUrl, child) {
  let output = '';
  child.stderr.on('data', chunk => { output += chunk.toString(); });
  for (let attempt = 0; attempt < 80; attempt++) {
    if (child.exitCode !== null) throw new Error(`AgentGuard process exited before becoming ready: ${output}`);
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return;
    } catch { /* server is still starting */ }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${baseUrl}: ${output}`);
}

async function stop(child) {
  if (!child || child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    new Promise(resolve => setTimeout(resolve, 5000)),
  ]);
}

async function main() {
  const scratch = `agentguard_rate_limit_test_${randomUUID().replaceAll('-', '')}`;
  const source = new URL(databaseUrl());
  const adminUrl = new URL(source); adminUrl.pathname = '/postgres';
  const admin = new Client({ connectionString: adminUrl.toString() });
  const children = [];
  let created = false;
  try {
    await admin.connect();
    await admin.query(`CREATE DATABASE "${scratch}"`); created = true;
    source.pathname = `/${scratch}`;
    const scratchUrl = source.toString();
    const setup = new Client({ connectionString: scratchUrl });
    await setup.connect();
    try {
      await setup.query(schema);
      await setup.query("INSERT INTO ag_workspaces(id,name) VALUES ('default','Rate limit test')");
      for (const companyId of ['company-a', 'company-b']) {
        await setup.query("INSERT INTO ag_companies(workspace_id,id,name,payload) VALUES ('default',$1,$1,'{}')", [companyId]);
        const credential = `${companyId}-credential`;
        await setup.query("INSERT INTO ag_agents(workspace_id,id,company_id,name,status,runtime_status,credential_hash,payload) VALUES ('default',$1,$2,$1,'registered','offline',$3,$4::jsonb)", [companyId, companyId, tokenHash(credential), JSON.stringify({ id: companyId, workspaceId: 'default', companyId, name: companyId, status: 'registered', runtimeStatus: 'offline', credentialHash: tokenHash(credential) })]);
      }
    } finally { await setup.end(); }

    const ports = [await freePort(), await freePort()];
    for (const port of ports) {
      const child = spawn(process.execPath, ['server.js'], {
        cwd: path.join(__dirname, '..'),
        env: {
          ...process.env,
          PORT: String(port),
          DATABASE_URL: scratchUrl,
          AGENTGUARD_STORAGE: 'postgres',
          AGENTGUARD_SHARED_RATE_LIMIT: 'true',
          AGENTGUARD_RATE_LIMIT: '100',
          AGENTGUARD_AGENT_RATE_LIMIT: '3',
          AGENTGUARD_COMPANY_RATE_LIMIT: '10',
          AGENTGUARD_WORKSPACE_RATE_LIMIT: '100',
          AGENTGUARD_REQUIRE_AUTH: 'false',
        },
        stdio: ['ignore', 'ignore', 'pipe'],
        windowsHide: true,
      });
      children.push(child);
    }
    const bases = ports.map(port => `http://127.0.0.1:${port}`);
    await Promise.all(children.map((child, index) => waitForHealth(bases[index], child)));

    const send = (base, companyId, count, label) => fetch(`${base}/api/gateway/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${companyId}-credential`, 'x-agentguard-workspace': 'default', 'x-agentguard-company': companyId, 'x-agentguard-agent': companyId },
      body: JSON.stringify(Array.from({ length: count }, (_, index) => ({ eventId: `${label}-${index}`, companyId, agentId: companyId, eventType: 'running', message: label }))),
    });

    assert.equal((await send(bases[0], 'company-a', 2, 'instance-one')).status, 202);
    const rejected = await send(bases[1], 'company-a', 2, 'instance-two');
    assert.equal(rejected.status, 429, 'the second process must see capacity spent through the first');
    assert.equal(rejected.headers.get('retry-after'), '60');
    assert.equal((await send(bases[1], 'company-b', 3, 'isolated-company')).status, 202, 'one company must not consume another company’s quota');

    const verify = new Client({ connectionString: scratchUrl });
    await verify.connect();
    try {
      const receipts = await verify.query("SELECT company_id,count(*)::int AS count FROM ag_telemetry_receipts GROUP BY company_id ORDER BY company_id");
      assert.deepEqual(receipts.rows, [{ company_id: 'company-a', count: 2 }, { company_id: 'company-b', count: 3 }]);
    } finally { await verify.end(); }
    console.log('PASS: shared agent limits work across two processes and preserve company isolation.');
  } finally {
    await Promise.all(children.map(stop));
    if (created) {
      await admin.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()', [scratch]);
      await admin.query(`DROP DATABASE "${scratch}"`);
      console.log('Scratch database removed.');
    }
    await admin.end();
  }
}

main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
