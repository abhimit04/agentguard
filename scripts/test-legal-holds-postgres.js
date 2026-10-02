// Exercises legal holds in a uniquely named scratch PostgreSQL database.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createHmac, randomUUID } = require('node:crypto');
const { Client, Pool } = require('pg');
const { requiredTables, restoreJson, verifyAudit } = require('./restore-drill-postgres');

const sourceUrl = new URL(process.env.DATABASE_URL || '');
if (!sourceUrl.hostname) throw new Error('DATABASE_URL is required');
const databaseName = `agentguard_legal_hold_test_${randomUUID().replaceAll('-', '')}`;
const restoreName = `agentguard_legal_hold_restore_test_${randomUUID().replaceAll('-', '')}`;
const adminUrl = new URL(sourceUrl); adminUrl.pathname = '/postgres';
const testUrl = new URL(sourceUrl); testUrl.pathname = `/${databaseName}`;
const admin = new Client({ connectionString: adminUrl.toString() });
const schema = fs.readFileSync(path.join(__dirname, '..', 'infra', 'postgres', '002-relational.sql'), 'utf8');

function cookie(secret, email) {
  const encoded = Buffer.from(JSON.stringify({ sub: email, email, name: email, createdAt: Date.now(), purpose: 'session' })).toString('base64url');
  return `agentguard_session=${encoded}.${createHmac('sha256', secret).update(encoded).digest('base64url')}`;
}

async function main() {
  let created = false; let restored = false; let storage; let server; let restorePool; let tempDirectory;
  try {
    await admin.connect();
    await admin.query(`CREATE DATABASE "${databaseName}"`);
    created = true;
    const client = new Client({ connectionString: testUrl.toString() });
    try {
      await client.connect();
      await client.query(schema);
      await client.query("INSERT INTO ag_workspaces(id,name) VALUES ('hold-test','Hold test'),('other-test','Other workspace')");
      await client.query(`INSERT INTO ag_memberships(id,workspace_id,email,role) VALUES
        ('hold-owner','hold-test','owner@example.test','owner'),
        ('hold-admin','hold-test','admin@example.test','admin'),
        ('hold-viewer','hold-test','viewer@example.test','viewer'),
        ('other-owner','other-test','other@example.test','owner')`);
    } finally { await client.end(); }

    process.env.DATABASE_URL = testUrl.toString();
    process.env.AGENTGUARD_STORAGE = 'postgres';
    process.env.AGENTGUARD_REQUIRE_AUTH = 'true';
    process.env.AGENTGUARD_DEFAULT_WORKSPACE_ID = 'hold-test';
    process.env.AGENTGUARD_OWNER_EMAIL = '';
    process.env.JWT_SECRET = 'legal-hold-test-session-secret-32-chars';
    storage = require('../storage');
    await storage.initializeStore();
    server = require('../server').server;
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const call = async (route, email, method = 'GET', data = null) => {
      const response = await fetch(`${base}${route}`, { method, headers: { cookie: cookie(process.env.JWT_SECRET, email), ...(data ? { 'Content-Type': 'application/json' } : {}) }, ...(data ? { body: JSON.stringify(data) } : {}) });
      return { status: response.status, body: await response.json() };
    };

    assert.equal((await call('/api/audit/legal-holds', 'viewer@example.test')).body.length, 0);
    const initialRetention = await call('/api/audit/retention', 'viewer@example.test');
    assert.equal(initialRetention.status, 200);
    assert.equal(initialRetention.body.retentionDays, null);
    assert.equal(initialRetention.body.cleanupEnabled, false);
    assert.equal((await call('/api/audit/retention', 'viewer@example.test', 'PUT', { retentionDays: 365, version: 0 })).status, 403);
    assert.equal((await call('/api/audit/retention', 'admin@example.test', 'PUT', { retentionDays: 1, version: 0 })).status, 400);
    const configuredRetention = await call('/api/audit/retention', 'admin@example.test', 'PUT', { retentionDays: 365, version: 0 });
    assert.equal(configuredRetention.status, 200, JSON.stringify(configuredRetention.body));
    assert.equal(configuredRetention.body.retentionDays, 365);
    assert.equal(configuredRetention.body.version, 1);
    assert.equal((await call('/api/audit/retention', 'admin@example.test', 'PUT', { retentionDays: 730, version: 0 })).status, 409);
    assert.equal((await call('/api/audit/retention', 'other@example.test')).body.retentionDays, null, 'retention must be workspace-scoped');
    assert.equal((await call('/api/audit/legal-holds', 'other@example.test')).body.length, 0);
    assert.equal((await call('/api/audit/legal-holds', 'viewer@example.test', 'POST', { reason: 'Client investigation' })).status, 403);
    const createdHold = await call('/api/audit/legal-holds', 'admin@example.test', 'POST', { reason: 'Client investigation', caseReference: 'CASE-123' });
    assert.equal(createdHold.status, 201, JSON.stringify(createdHold.body));
    assert.equal(createdHold.body.status, 'active');
    assert.equal((await call('/api/audit/legal-holds', 'other@example.test')).body.length, 0, 'another workspace cannot see this hold');
    assert.equal((await call(`/api/audit/legal-holds/${createdHold.body.id}/release`, 'admin@example.test', 'POST', { reason: 'Case complete' })).status, 403);
    assert.equal((await call(`/api/audit/legal-holds/${createdHold.body.id}/release`, 'other@example.test', 'POST', { reason: 'Case complete' })).status, 404);
    assert.equal((await call(`/api/audit/legal-holds/${createdHold.body.id}/release`, 'owner@example.test', 'POST', { reason: 'Case complete' })).status, 200);
    assert.equal((await call(`/api/audit/legal-holds/${createdHold.body.id}/release`, 'owner@example.test', 'POST', { reason: 'Case complete' })).status, 404);
    const activeHold = await call('/api/audit/legal-holds', 'owner@example.test', 'POST', { reason: 'Preserve records for an open case', caseReference: 'CASE-456' });
    assert.equal(activeHold.status, 201);
    const heldRetention = await call('/api/audit/retention', 'viewer@example.test');
    assert.equal(heldRetention.body.activeHolds, 1);
    assert.equal(heldRetention.body.cleanupEnabled, false);
    assert.ok(heldRetention.body.blockers.some(reason => reason.includes('legal hold')));

    const triggerClient = new Client({ connectionString: testUrl.toString() });
    try {
      await triggerClient.connect();
      await triggerClient.query(`CREATE FUNCTION reject_hold_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.event_type IN ('audit.legal_hold.created','audit.retention.configured') THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`);
      await triggerClient.query('CREATE TRIGGER reject_hold_audit_before_insert BEFORE INSERT ON ag_audit_events FOR EACH ROW EXECUTE FUNCTION reject_hold_audit()');
      const rejected = await call('/api/audit/legal-holds', 'owner@example.test', 'POST', { reason: 'This must roll back' });
      assert.equal(rejected.status, 503);
      assert.equal((await call('/api/audit/retention', 'owner@example.test', 'PUT', { retentionDays: 730, version: 1 })).status, 503);
      const retentionRow = await triggerClient.query("SELECT audit_retention_days,retention_version FROM ag_workspaces WHERE id='hold-test'");
      assert.equal(retentionRow.rows[0].audit_retention_days, 365);
      assert.equal(retentionRow.rows[0].retention_version, 1);
      const rows = await triggerClient.query("SELECT count(*)::int AS n FROM ag_audit_legal_holds WHERE workspace_id='hold-test'");
      assert.equal(rows.rows[0].n, 2, 'failed audit write must roll back the hold');
      const audit = await triggerClient.query("SELECT event_type,count(*)::int AS n FROM ag_audit_events WHERE workspace_id='hold-test' AND event_type LIKE 'audit.legal_hold.%' GROUP BY event_type");
      assert.deepEqual(Object.fromEntries(audit.rows.map(row => [row.event_type, row.n])), { 'audit.legal_hold.created': 2, 'audit.legal_hold.released': 1 });
    } finally { await triggerClient.end(); }

    tempDirectory = await fsp.mkdtemp(path.join(os.tmpdir(), 'agentguard-legal-hold-restore-'));
    const backupPath = path.join(tempDirectory, 'scratch-snapshot.json');
    const snapshot = { createdAt: new Date().toISOString(), schema: 12, tables: {} };
    const source = new Client({ connectionString: testUrl.toString() });
    try {
      await source.connect();
      for (const table of requiredTables) snapshot.tables[table] = (await source.query(`SELECT * FROM "${table}"`)).rows;
    } finally { await source.end(); }
    await fsp.writeFile(backupPath, JSON.stringify(snapshot), { flag: 'wx' });
    await admin.query(`CREATE DATABASE "${restoreName}"`);
    restored = true;
    const restoreUrl = new URL(sourceUrl); restoreUrl.pathname = `/${restoreName}`;
    restorePool = new Pool({ connectionString: restoreUrl.toString() });
    const expected = await restoreJson(restorePool, backupPath);
    assert.equal(expected.ag_audit_legal_holds, 2);
    const recovered = await restorePool.query("SELECT id,reason,case_reference,released_at FROM ag_audit_legal_holds WHERE workspace_id='hold-test' ORDER BY id");
    assert.equal(recovered.rowCount, 2);
    assert.equal(recovered.rows.filter(row => !row.released_at).length, 1);
    assert.equal(recovered.rows.find(row => row.id === activeHold.body.id)?.case_reference, 'CASE-456');
    const restoredPolicy = await restorePool.query("SELECT audit_retention_days,retention_version FROM ag_workspaces WHERE id='hold-test'");
    assert.equal(restoredPolicy.rows[0].audit_retention_days, 365);
    assert.equal(restoredPolicy.rows[0].retention_version, 1);
    const restoredAudit = await verifyAudit(restorePool);
    assert.equal(restoredAudit.find(row => row.workspaceId === 'hold-test')?.checked, 4);
    console.log('Retention and legal holds passed: roles, tenant isolation, optimistic edits, atomic audit, rollback, and scratch JSON backup/restore.');
  } finally {
    if (server?.listening) await new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); });
    if (restorePool) await restorePool.end().catch(() => {});
    if (storage) await storage.closePostgres().catch(() => {});
    if (tempDirectory) {
      await fsp.rm(path.join(tempDirectory, 'scratch-snapshot.json'), { force: true });
      await fsp.rmdir(tempDirectory).catch(() => {});
    }
    if (restored) {
      assert.match(restoreName, /^agentguard_legal_hold_restore_test_[a-f0-9]{32}$/);
      await admin.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()', [restoreName]);
      await admin.query(`DROP DATABASE IF EXISTS "${restoreName}"`);
    }
    if (created) {
      assert.match(databaseName, /^agentguard_legal_hold_test_[a-f0-9]{32}$/);
      await admin.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()', [databaseName]);
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}"`);
      console.log('Scratch legal-hold and restore databases removed.');
    }
    await admin.end().catch(() => {});
  }
}

main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
