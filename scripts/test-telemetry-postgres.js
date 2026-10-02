// Runs only in a freshly created scratch database. Never resets live tables.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { promisify } = require('node:util');
const { execFile } = require('node:child_process');
const { Client } = require('pg');
const runChild = promisify(execFile);
const relationalSchema = fs.readFileSync(path.join(__dirname, '..', 'infra', 'postgres', '002-relational.sql'), 'utf8');

async function prepareRelationalFixture(connectionString) {
  const client = new Client({ connectionString });
  try {
    await client.connect();
    await client.query(relationalSchema);
    await client.query(`INSERT INTO ag_workspaces(id,name) VALUES ('default','Telemetry test bootstrap') ON CONFLICT DO NOTHING`);
  } finally { await client.end(); }
}

function connection() {
  return process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@127.0.0.1:${process.env.POSTGRES_PORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}`;
}
async function exercise(restart = false) {
  process.env.AGENTGUARD_STORAGE = 'postgres';
  process.env.AGENTGUARD_API_KEY = 'telemetry-isolated-test-integration-key';
  const storage = require('../storage');
  await storage.initializeStore();
  const repo = require('../repositories/telemetry');
  const { normalizeEnvelope, tokenHash } = require('../gateway');
  const { verifyAuditChain } = require('./verify-audit-chain');
  const { server } = require('../server');
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const identity = { workspaceId: 'test-a', companyId: 'company', agentId: 'agent' };
  const headers = { 'content-type': 'application/json', 'x-agentguard-workspace': 'test-a', 'x-agentguard-company': 'company', authorization: 'Bearer credential-a' };
  const event = (id, overrides = {}) => normalizeEnvelope({ eventId: id, companyId: 'company', agentId: 'agent', eventType: 'task.started', metrics: { inputTokens: 5 }, ...overrides });
  const post = (route, payload, extra = {}) => fetch(base + route, { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(payload) });
  try {
    if (restart) {
      const response = await post('/api/gateway/agents/agent/events', event('retry-1'));
      assert.equal(response.status, 202);
      assert.equal((await response.json()).duplicate, true);
      assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE payload->>'eventId'='retry-1' AND workspace_id='test-a'")).rows[0].n, 1);
      console.log('Fresh process: durable retry receipt and audit survived restart.');
      return;
    }
    for (const workspace of ['test-a', 'test-b']) {
      const credential = workspace === 'test-a' ? 'credential-a' : 'credential-b';
      await storage.postgresQuery('INSERT INTO ag_workspaces(id,name) VALUES($1,$1)', [workspace]);
      await storage.postgresQuery("INSERT INTO ag_companies(workspace_id,id,name,payload) VALUES($1,'company','Test company','{}')", [workspace]);
      const payload = { id: 'agent', workspaceId: workspace, companyId: 'company', name: 'Test agent', status: 'registered', runtimeStatus: 'offline', credentialHash: tokenHash(credential) };
      await storage.postgresQuery("INSERT INTO ag_agents(workspace_id,id,company_id,name,status,runtime_status,credential_hash,payload) VALUES($1,'agent','company','Test agent','registered','offline',$2,$3::jsonb)", [workspace, tokenHash(credential), JSON.stringify(payload)]);
    }
    await storage.postgresQuery(`CREATE FUNCTION reject_compatibility_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Compatibility write prohibited'; END $$;
      DO $$ BEGIN IF to_regclass('public.agentguard_records') IS NOT NULL THEN CREATE TRIGGER no_compatibility_write BEFORE INSERT OR UPDATE OR DELETE ON agentguard_records FOR EACH STATEMENT EXECUTE FUNCTION reject_compatibility_write(); END IF; END $$;
      CREATE FUNCTION inject_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.payload->>'eventId'='fail-audit' OR NEW.message='Injected runtime failure' THEN RAISE EXCEPTION 'Injected audit failure'; END IF; RETURN NEW; END $$;
      CREATE TRIGGER audit_failure BEFORE INSERT ON ag_audit_events FOR EACH ROW EXECUTE FUNCTION inject_audit_failure();`);
    const first = await post('/api/gateway/agents/agent/events', event('retry-1'));
    assert.equal(first.status, 202); assert.equal((await first.json()).accepted, 1);
    const parallel = await Promise.all(Array.from({ length: 8 }, () => repo.ingest(identity, [event('concurrent')], { token: 'credential-a' })));
    assert.equal(parallel.reduce((sum, result) => sum + result.accepted, 0), 1);
    assert.equal(parallel.reduce((sum, result) => sum + result.duplicates, 0), 7);
    const before = await repo.readAgent(identity, { token: 'credential-a' });
    const cachedBefore = structuredClone(storage.readStore().agents);
    const failed = await post('/api/gateway/events', [event('batch-rollback'), event('fail-audit')]);
    assert.equal(failed.status, 503);
    assert.deepEqual(await repo.readAgent(identity, { token: 'credential-a' }), before);
    assert.deepEqual(storage.readStore().agents, cachedBefore, 'failed transaction must not publish cached state');
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_telemetry_receipts WHERE event_id IN ('batch-rollback','fail-audit')")).rows[0].n, 0);
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE payload->>'eventId' IN ('batch-rollback','fail-audit')")).rows[0].n, 0);
    await assert.rejects(repo.updateRuntime(identity, (agent, add) => { agent.status = 'registered'; add('action', 'Injected runtime failure', { eventType: 'agent.activity' }); }));
    assert.deepEqual(await repo.readAgent(identity, { token: 'credential-a' }), before);
    assert.equal((await post('/api/gateway/agents/agent/events', event('tenant-escape'), { 'x-agentguard-workspace': 'test-b' })).status, 401);
    assert.equal((await post('/api/gateway/agents/agent/events', event('header-escape'), { 'x-agentguard-agent': 'another-agent' })).status, 403);
    assert.equal((await post('/api/gateway/agents/agent/events', event('body-escape', { companyId: 'other' }))).status, 403);
    const other = await repo.ingest({ ...identity, workspaceId: 'test-b' }, [event('retry-1')], { token: 'credential-b' });
    assert.equal(other.accepted, 1, 'event IDs are scoped to the tenant and agent');
    await assert.rejects(repo.readAgent({ agentId: 'agent', companyId: 'company' }, { token: 'credential-a' }), error => error.statusCode === 409);
    const heart = await post('/api/gateway/agents/agent/heartbeat', { eventId: 'heartbeat-1' });
    assert.equal(heart.status, 202);
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE event_type='heartbeat'")).rows[0].n, 0);
    for (const alias of ['/api/agent-events', '/api/v1/events']) {
      const response = await post(alias, { ...event(alias), workspaceId: 'test-a', eventType: 'completed' }, { authorization: 'Bearer telemetry-isolated-test-integration-key' });
      assert.equal(response.status, 201);
    }
    const failure = await post('/api/gateway/agents/agent/events', event('agent-failed', { eventType: 'task.failed' }));
    assert.equal(failure.status, 202);
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_incidents WHERE workspace_id='test-a'")).rows[0].n, 1);
    const managed = await repo.updateRuntime(identity, (agent, add) => {
      agent.status = 'healthy'; agent.runtimeStatus = 'running'; agent.lastSeenAt = '2020-01-01T00:00:00.000Z';
      agent.connection = { mode: 'gateway', desiredState: 'running' };
      add('action', 'Managed runtime snapshot', { eventType: 'agent.activity' });
    });
    assert.equal(managed.events.length, 1);
    await repo.expireStates(60000, 60000);
    assert.equal((await repo.readAgent(identity, { token: 'credential-a' })).runtimeStatus, 'offline');
    await storage.postgresQuery("UPDATE ag_agents SET credential_hash=$1 WHERE workspace_id='test-a' AND id='agent'", [tokenHash('rotated')]);
    assert.equal((await post('/api/gateway/agents/agent/events', event('stale-credential'))).status, 401, 'credential revocation must not depend on cached state');
    await storage.postgresQuery("UPDATE ag_agents SET credential_hash=$1 WHERE workspace_id='test-a' AND id='agent'", [tokenHash('credential-a')]);
    for (const workspace of ['test-a', 'test-b']) assert.equal((await verifyAuditChain(workspace)).ok, true);
    for (const id of ['retry-1', 'concurrent', '/api/agent-events', '/api/v1/events', 'agent-failed']) {
      assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test-a' AND payload->>'eventId'=$1", [id])).rows[0].n, 1, `accepted event ${id} must have exactly one audit record`);
    }
    await storage.postgresQuery("UPDATE ag_companies SET gateway_credential_hash=$1 WHERE workspace_id='test-a' AND id='company'", [tokenHash('company-credential')]);
    const companyResponse = await post('/api/gateway/events', event('company-auth'), { authorization: 'Bearer company-credential' });
    assert.equal(companyResponse.status, 202);
    assert.equal((await post('/api/gateway/events', event('company-escape'), { authorization: 'Bearer company-credential', 'x-agentguard-workspace': 'test-b' })).status, 401);
    await storage.postgresQuery("UPDATE ag_agents SET payload=payload || '{\"archived\":true}'::jsonb WHERE workspace_id='test-a' AND id='agent'");
    assert.equal((await post('/api/gateway/agents/agent/events', event('archived-agent'))).status, 409);
    await storage.postgresQuery("UPDATE ag_agents SET payload=payload || '{\"archived\":false}'::jsonb WHERE workspace_id='test-a' AND id='agent'");
    assert.equal((await verifyAuditChain('test-a')).ok, true);
    console.log('PASS: atomic ingestion/batch rollback, audit failures, runtime rollback, concurrent retries, tenant isolation, credential revocation, heartbeat suppression, legacy aliases, incident persistence, expiry, and hash chains.');
  } finally {
    await new Promise(resolve => server.close(resolve));
    await storage.closePostgres();
  }
}

async function main() {
  if (process.argv.includes('--restart-probe')) return exercise(true);
  const scratch = `agentguard_telemetry_test_${randomUUID().replaceAll('-', '')}`;
  const base = new URL(connection()); const adminUrl = new URL(base); adminUrl.pathname = '/postgres';
  const admin = new Client({ connectionString: adminUrl.toString() });
  let created = false;
  try {
    await admin.connect();
    await admin.query(`CREATE DATABASE "${scratch}"`); created = true;
    base.pathname = `/${scratch}`; process.env.DATABASE_URL = base.toString();
    await prepareRelationalFixture(base.toString());
    await exercise();
    const result = await runChild(process.execPath, [__filename, '--restart-probe'], { env: { ...process.env }, timeout: 60000, windowsHide: true });
    console.log(result.stdout.trim());
  } finally {
    if (created) {
      assert.match(scratch, /^agentguard_telemetry_test_[a-f0-9]{32}$/);
      await admin.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()', [scratch]);
      await admin.query(`DROP DATABASE "${scratch}"`);
      console.log('Scratch database removed.');
    }
    await admin.end();
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
