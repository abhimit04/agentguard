// End-to-end signed audit export test. All database and key files are isolated
// scratch artifacts; the configured application database is never modified.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createHmac, generateKeyPairSync, randomUUID } = require('node:crypto');
const { Client } = require('pg');
const { verifyExport } = require('./verify-audit-export');
const { archiveExport, verifyContinuation } = require('./audit-archive');

const sourceUrl = new URL(process.env.DATABASE_URL || '');
if (!sourceUrl.hostname) throw new Error('DATABASE_URL is required');
const databaseName = `agentguard_audit_export_test_${randomUUID().replaceAll('-', '')}`;
const adminUrl = new URL(sourceUrl); adminUrl.pathname = '/postgres';
const testUrl = new URL(sourceUrl); testUrl.pathname = `/${databaseName}`;
const admin = new Client({ connectionString: adminUrl.toString() });
const relationalSchema = fs.readFileSync(path.join(__dirname, '..', 'infra', 'postgres', '002-relational.sql'), 'utf8');

async function prepareRelationalFixture() {
  const client = new Client({ connectionString: testUrl.toString() });
  try {
    await client.connect();
    await client.query(relationalSchema);
    await client.query(`INSERT INTO ag_workspaces(id,name) VALUES ('export-test','Audit export test')`);
    await client.query(`INSERT INTO ag_memberships(id,workspace_id,email,display_name,role) VALUES ('exporter-1','export-test','exporter@example.test','Evidence Exporter','owner')`);
  } finally { await client.end(); }
}

function signedSessionCookie(secret, user) {
  const encoded = Buffer.from(JSON.stringify({ ...user, createdAt: Date.now(), purpose: 'session' })).toString('base64url');
  const signature = createHmac('sha256', secret).update(encoded).digest('base64url');
  return `agentguard_session=${encoded}.${signature}`;
}

async function main() {
  let created = false;
  let server; let storage;
  let tempDirectory;
  try {
    await admin.connect();
    await admin.query(`CREATE DATABASE "${databaseName}"`);
    created = true;
    await prepareRelationalFixture();

    process.env.DATABASE_URL = testUrl.toString();
    process.env.AGENTGUARD_STORAGE = 'postgres';
    process.env.AGENTGUARD_REQUIRE_AUTH = 'true';
    process.env.AGENTGUARD_DEFAULT_WORKSPACE_ID = 'export-test';
    process.env.JWT_SECRET = 'audit-export-test-session-secret-32-chars';
    process.env.AGENTGUARD_OWNER_EMAIL = '';

    tempDirectory = await fsp.mkdtemp(path.join(os.tmpdir(), 'agentguard-audit-export-test-'));
    const privatePath = path.join(tempDirectory, 'audit-private.pem');
    const publicPath = path.join(tempDirectory, 'audit-public.pem');
    const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    });
    await fsp.writeFile(privatePath, privateKey, { mode: 0o600, flag: 'wx' });
    await fsp.writeFile(publicPath, publicKey, { mode: 0o600, flag: 'wx' });
    process.env.AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_FILE = privatePath;
    process.env.AGENTGUARD_AUDIT_SIGNING_KEY_ID = `test-${randomUUID()}`;

    storage = require('../storage');
    await storage.initializeStore();
    const governance = require('../repositories/governance');
    const { server: appServer } = require('../server');
    server = appServer;
    await governance.appendEvent({ id: 'export-event-1', workspaceId: 'export-test', kind: 'action', eventType: 'test.started', actor: 'test', message: 'First export fixture event', createdAt: new Date().toISOString() });
    await governance.appendEvent({ id: 'export-event-2', workspaceId: 'export-test', kind: 'action', eventType: 'test.completed', actor: 'test', message: 'Second export fixture event', createdAt: new Date().toISOString() });
    await governance.flushAudit();

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const cookie = signedSessionCookie(process.env.JWT_SECRET, { sub: 'exporter-subject', email: 'exporter@example.test', name: 'Evidence Exporter' });
    const response = await fetch(`${baseUrl}/api/evidence/audit.ndjson?fromSequence=1&toSequence=2`, { headers: { cookie } });
    const body = await response.text();
    assert.equal(response.status, 200, body);
    assert.match(response.headers.get('content-type') || '', /application\/x-ndjson/);

    const exportPath = path.join(tempDirectory, 'audit-export.ndjson');
    await fsp.writeFile(exportPath, body, { flag: 'wx' });
    const verified = await verifyExport(exportPath, publicPath);
    assert.deepEqual({ ok: verified.ok, eventCount: verified.eventCount, firstSequence: verified.firstSequence, lastSequence: verified.lastSequence, signingKeyId: verified.signingKeyId }, {
      ok: true, eventCount: 2, firstSequence: 1, lastSequence: 2, signingKeyId: process.env.AGENTGUARD_AUDIT_SIGNING_KEY_ID
    });

    const lines = body.trimEnd().split('\n');
    const eventRecord = JSON.parse(lines[1]);
    eventRecord.event.message = 'tampered event fixture';
    lines[1] = require('../audit-integrity').stableStringify(eventRecord);
    const tamperedPath = path.join(tempDirectory, 'tampered-audit-export.ndjson');
    await fsp.writeFile(tamperedPath, `${lines.join('\n')}\n`, { flag: 'wx' });
    await assert.rejects(verifyExport(tamperedPath, publicPath), /event bytes do not match the manifest digest/);

    const archived = await archiveExport(exportPath, publicPath, path.join(tempDirectory, 'archive'), privatePath, process.env.AGENTGUARD_AUDIT_SIGNING_KEY_ID);
    const continuationResponse = await fetch(`${baseUrl}/api/evidence/audit.ndjson?fromSequence=3&toSequence=3`, { headers: { cookie } });
    const continuationBody = await continuationResponse.text();
    assert.equal(continuationResponse.status, 200, continuationBody);
    const continuationPath = path.join(tempDirectory, 'continuation-audit-export.ndjson');
    await fsp.writeFile(continuationPath, continuationBody, { flag: 'wx' });
    const continued = await verifyContinuation(archived.checkpointPath, continuationPath, publicPath);
    assert.equal(continued.archivedThrough, 2);
    assert.equal(continued.continuedThrough, 3);

    const exportAudit = await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='export-test' AND event_type='evidence.audit_exported'");
    assert.equal(exportAudit.rows[0].n, 2, 'both export requests must be durably audited');
    console.log('Signed audit export passed: authenticated download, offline signature/chain verification, tamper rejection, archived checkpoint, linked continuation, and export audit events.');
  } finally {
    if (server?.listening) await new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); });
    if (storage) await storage.closePostgres().catch(() => {});
    if (tempDirectory) {
      await fsp.rm(path.join(tempDirectory, 'archive'), { recursive: true, force: true });
      for (const filename of ['audit-private.pem', 'audit-public.pem', 'audit-export.ndjson', 'tampered-audit-export.ndjson', 'continuation-audit-export.ndjson']) await fsp.rm(path.join(tempDirectory, filename), { force: true });
      await fsp.rmdir(tempDirectory).catch(() => {});
    }
    if (created) {
      assert.match(databaseName, /^agentguard_audit_export_test_[a-f0-9]{32}$/);
      await admin.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()', [databaseName]);
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}"`);
      console.log('Scratch database and temporary export artifacts removed.');
    }
    await admin.end().catch(() => {});
  }
}

main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
