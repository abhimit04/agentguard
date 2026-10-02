const fs = require('node:fs');
const path = require('node:path');
const { randomBytes, randomUUID } = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { pipeline } = require('node:stream/promises');
const { createGunzip } = require('node:zlib');
const { Pool } = require('pg');
const { auditHash } = require('../audit-integrity');
const { createManifest, manifestPath, verifyManifestSignature } = require('./postgres-backup-manifest');

const root = path.join(__dirname, '..');
const backupDirectory = path.join(root, 'backups');
const requiredTables = ['ag_workspaces', 'ag_memberships', 'ag_companies', 'ag_agents', 'ag_policies', 'ag_approvals', 'ag_governed_actions', 'ag_assessments', 'ag_assessment_revisions', 'ag_incidents', 'ag_alerts', 'ag_alert_deliveries', 'ag_audit_events', 'ag_audit_legal_holds', 'ag_telemetry_receipts'];
const addedLaterTables = new Set(['ag_telemetry_receipts', 'ag_audit_legal_holds', 'ag_assessment_revisions']);

function discoverBackups() {
  const found = [];
  function walk(directory) {
    if (!fs.existsSync(directory)) return;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(file);
      else if (/^postgres-cutover-.*\.json$/.test(entry.name) || entry.name.endsWith('.sql.gz')) {
        let stat;
        try { stat = fs.statSync(file); }
        catch (error) { if (['EACCES', 'ENOENT'].includes(error.code)) continue; throw error; }
        if (stat.size > 0) found.push({ name: path.relative(backupDirectory, file), path: file, size: stat.size, modified: stat.mtimeMs });
      }
    }
  }
  walk(backupDirectory);
  return found.sort((a, b) => b.modified - a.modified);
}

function selectBackup() {
  const requested = process.argv.find((arg, index) => process.argv[index - 1] === '--backup');
  if (!requested) {
    const backups = discoverBackups();
    if (!backups.length) throw new Error('No non-empty PostgreSQL backup found under backups/');
    return backups[0];
  }
  const resolved = path.resolve(root, requested);
  const relative = path.relative(backupDirectory, resolved);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('--backup must identify a file inside backups/');
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.size === 0) throw new Error('Selected backup is empty or not a file');
  if (!(/^postgres-cutover-.*\.json$/.test(path.basename(resolved)) || resolved.endsWith('.sql.gz'))) throw new Error('Supported backups are postgres-cutover-*.json and .sql.gz');
  return { name: path.relative(backupDirectory, resolved), path: resolved, size: stat.size, modified: stat.mtimeMs };
}

function connectionUrl(databaseName) {
  const base = process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@127.0.0.1:${process.env.POSTGRES_PORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}`;
  const url = new URL(base);
  url.pathname = `/${databaseName}`;
  return url;
}

async function insertRows(client, table, rows) {
  if (!rows.length) return;
  const columns = Object.keys(rows[0]);
  const names = columns.map(column => `"${column.replaceAll('"', '""')}"`).join(',');
  const batchSize = Math.min(250, Math.max(1, Math.floor(60000 / columns.length)));
  for (let offset = 0; offset < rows.length; offset += batchSize) {
    const batch = rows.slice(offset, offset + batchSize), values = [];
    const tuples = batch.map((row, rowIndex) => `(${columns.map((column, columnIndex) => { values.push(row[column]); return `$${rowIndex * columns.length + columnIndex + 1}`; }).join(',')})`);
    await client.query(`INSERT INTO "${table}" (${names}) VALUES ${tuples.join(',')}`, values);
  }
}

async function verifyAudit(client) {
  const workspaces = await client.query('SELECT id FROM ag_workspaces ORDER BY id'), results = [];
  for (const workspace of workspaces.rows) {
    const events = await client.query('SELECT workspace_id,id,previous_hash,event_hash,payload FROM ag_audit_events WHERE workspace_id=$1 ORDER BY chain_sequence', [workspace.id]);
    let previousHash = null;
    for (const row of events.rows) {
      if (row.previous_hash !== previousHash) throw new Error(`Audit previous-hash mismatch at event ${row.id}`);
      if (row.event_hash !== auditHash(previousHash, row.payload, row.workspace_id)) throw new Error(`Audit event hash mismatch at event ${row.id}`);
      previousHash = row.event_hash;
    }
    results.push({ workspaceId: workspace.id, checked: events.rowCount, head: previousHash });
  }
  return results;
}

function runRestoreProcess(backupPath, scratchName, sourceUrl) {
  const user = decodeURIComponent(sourceUrl.username || process.env.POSTGRES_USER || 'agentguard');
  const psqlArgs = ['--no-psqlrc', '-v', 'ON_ERROR_STOP=1', '-h', sourceUrl.hostname, '-p', sourceUrl.port || '5432', '-U', user, '-d', scratchName];
  const hasPsql = spawnSync('psql', ['--version'], { stdio: 'ignore', windowsHide: true }).status === 0;
  const dockerContainer = process.env.AGENTGUARD_RESTORE_DOCKER_CONTAINER || '';
  const hasDocker = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { cwd: root, stdio: 'ignore', windowsHide: true }).status === 0;
  if (dockerContainer && (!/^[A-Za-z0-9_.-]+$/.test(dockerContainer) || !hasDocker)) throw new Error('AGENTGUARD_RESTORE_DOCKER_CONTAINER must be a safe container name/ID and Docker must be available');
  const hasDockerCompose = !dockerContainer && spawnSync('docker', ['compose', 'version'], { cwd: root, stdio: 'ignore', windowsHide: true }).status === 0;
  const localComposeDatabase = ['localhost', '127.0.0.1', '::1'].includes(sourceUrl.hostname) && (sourceUrl.port || '5432') === (process.env.POSTGRES_PORT || '5432');
  if (!hasPsql && !dockerContainer && !(hasDockerCompose && localComposeDatabase)) throw new Error('Restoring .sql.gz requires psql in PATH, an explicitly configured Docker restore container, or Docker Compose CLI for the local Compose Postgres service. No compatible restore client is available. The scratch database will be cleaned up.');
  const child = dockerContainer
    ? spawn('docker', ['exec', '-i', dockerContainer, 'psql', '--no-psqlrc', '-v', 'ON_ERROR_STOP=1', '-U', user, '-d', scratchName], { cwd: root, env: process.env, windowsHide: true, stdio: ['pipe', 'ignore', 'pipe'] })
    : hasPsql
    ? spawn('psql', psqlArgs, { cwd: root, env: { ...process.env, PGPASSWORD: decodeURIComponent(sourceUrl.password) }, windowsHide: true, stdio: ['pipe', 'ignore', 'pipe'] })
    : spawn('docker', ['compose', 'exec', '-T', 'postgres', 'sh', '-lc', 'exec psql --no-psqlrc -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$1"', 'restore-drill', scratchName], { cwd: root, env: process.env, windowsHide: true, stdio: ['pipe', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4000); });
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => code === 0 ? resolve() : reject(new Error(`PostgreSQL restore client exited with status ${code}: ${stderr.trim() || 'no diagnostic'}`)));
  });
  return Promise.all([pipeline(fs.createReadStream(backupPath), createGunzip(), child.stdin), exited]);
}

async function restoreJson(drill, backupPath) {
  const snapshot = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
  for (const table of requiredTables) if (!Array.isArray(snapshot.tables?.[table]) && !addedLaterTables.has(table)) throw new Error(`JSON backup is missing ${table}; create a fresh backup before the drill`);
  const schema = `${fs.readFileSync(path.join(root, 'infra', 'postgres', 'init.sql'), 'utf8')}\n${fs.readFileSync(path.join(root, 'infra', 'postgres', '002-relational.sql'), 'utf8')}`;
  await drill.query(schema);
  const client = await drill.connect();
  try {
    await client.query('BEGIN');
    for (const table of requiredTables) await insertRows(client, table, snapshot.tables[table] || []);
    await client.query("SELECT setval(pg_get_serial_sequence('ag_audit_events','chain_sequence'), GREATEST(COALESCE((SELECT max(chain_sequence) FROM ag_audit_events), 1), 1), true)");
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  return Object.fromEntries(requiredTables.filter(table => Array.isArray(snapshot.tables[table])).map(table => [table, snapshot.tables[table].length]));
}

async function governedWriteSmoke(drill, scratchName, sourceUrl) {
  const workspaceId = `restore-drill-${randomBytes(6).toString('hex')}`;
  await drill.query('INSERT INTO ag_workspaces(id,name) VALUES ($1,$2)', [workspaceId, 'Temporary restore drill workspace']);
  const oldUrl = process.env.DATABASE_URL, oldStorage = process.env.AGENTGUARD_STORAGE;
  process.env.DATABASE_URL = connectionUrl(scratchName).toString(); process.env.AGENTGUARD_STORAGE = 'postgres';
  let storage;
  try {
    storage = require('../storage');
    await storage.initializeStore();
    const governance = require('../repositories/governance');
    const agentId = 'restore-drill-agent', policyId = randomUUID();
    await storage.postgresQuery('INSERT INTO ag_companies(workspace_id,id,name,payload) VALUES ($1,$2,$3,$4::jsonb)', [workspaceId, 'restore-drill-company', 'Restore drill', '{}']);
    await storage.postgresQuery('INSERT INTO ag_agents(workspace_id,id,company_id,name,team,status,payload) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)', [workspaceId, agentId, 'restore-drill-company', 'Restore drill agent', 'drill', 'registered', JSON.stringify({ id: agentId, name: 'Restore drill agent' })]);
    await governance.upsertPolicy({ id: policyId, workspaceId, agentId, name: 'Restore drill approval', effect: 'require_approval', enabled: true, version: 1, priority: 100, actionType: 'tool.call', resourcePattern: 'tool:restore-drill' });
    const action = { actionRef: `restore-${randomUUID()}`, actionType: 'tool.call', action: 'Write restore drill marker', resource: 'tool:restore-drill', tool: 'restore-drill' };
    const options = { workspaceId, agentId, input: action, resource: action.resource, approvalTtlMs: 60_000, toolPermission: () => ({ allowed: true, tool: action.tool, grants: [action.tool] }), matchingPolicy: policies => policies.find(item => item.id === policyId), exceedsBudget: () => null };
    const request = await governance.checkGovernedAction(options);
    if (request.outcome !== 'awaiting_approval') throw new Error(`Restore governed check failed: ${request.outcome}`);
    const decision = await governance.decideApprovalWithAudit(request.approvalId, workspaceId, { status: 'approved', decision: 'approved', decidedBy: 'restore-drill-reviewer', rationale: 'Scratch restore validation', agentName: 'Restore drill agent' });
    if (decision.outcome !== 'decided') throw new Error(`Restore approval failed: ${decision.outcome}`);
    const resumed = await governance.checkGovernedAction(options);
    if (resumed.outcome !== 'ready_to_execute') throw new Error(`Restore resume failed: ${resumed.outcome}`);
    const claim = await governance.claimGovernedAction({ workspaceId, agentId, actionRef: action.actionRef, actionType: action.actionType, action: action.action, resource: action.resource, executionId: randomUUID(), auditId: randomUUID() });
    if (claim.outcome !== 'claimed') throw new Error(`Restore claim failed: ${claim.outcome}`);
    const completed = await governance.completeGovernedAction({ workspaceId, agentId, executionId: claim.action.executionId, success: true, result: { restored: true }, auditId: randomUUID() });
    if (completed.outcome !== 'completed') throw new Error(`Restore completion failed: ${completed.outcome}`);
    const persisted = await storage.postgresQuery("SELECT state,payload->'result'->>'restored' AS restored FROM ag_governed_actions WHERE workspace_id=$1 AND action_ref=$2", [workspaceId, action.actionRef]);
    if (persisted.rows[0]?.state !== 'completed' || persisted.rows[0]?.restored !== 'true') throw new Error('Governed result did not persist in scratch database');
    await storage.closePostgres(); storage = null;
    return { passed: true, workflow: ['approval.required', 'approval.approved', 'execution.claimed', 'execution.completed'] };
  } finally {
    if (storage) await storage.closePostgres().catch(() => {});
    if (oldUrl === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = oldUrl;
    if (oldStorage === undefined) delete process.env.AGENTGUARD_STORAGE; else process.env.AGENTGUARD_STORAGE = oldStorage;
  }
}

async function runRestoreDrill() {
  const startedAt = Date.now();
  if (!(process.env.AGENTGUARD_STORAGE === 'postgres' || process.env.DATABASE_URL)) throw new Error('PostgreSQL storage is not enabled');
  const backup = selectBackup();
  const sqlManifest = backup.path.endsWith('.sql.gz') ? await createManifest(backup.path) : null;
  if (sqlManifest) {
    const signature = verifyManifestSignature(sqlManifest.document, process.env.AGENTGUARD_BACKUP_MANIFEST_PUBLIC_KEY_FILE);
    if (['1', 'true', 'yes'].includes(String(process.env.AGENTGUARD_REQUIRE_SIGNED_BACKUP_MANIFEST || '').toLowerCase()) && !signature.signed) throw new Error('Signed backup manifest is required for this restore drill');
  }
  const configuredDatabase = process.env.DATABASE_URL ? new URL(process.env.DATABASE_URL).pathname.slice(1) : (process.env.POSTGRES_DB || 'agentguard');
  const sourceUrl = connectionUrl(decodeURIComponent(configuredDatabase));
  const scratchName = `agentguard_restore_${Date.now()}_${randomBytes(3).toString('hex')}`;
  const admin = new Pool({ connectionString: connectionUrl('postgres').toString(), max: 1 });
  let drill, primaryError = null, cleanupError = null, report;
  try {
    await admin.query(`CREATE DATABASE "${scratchName}"`);
    drill = new Pool({ connectionString: connectionUrl(scratchName).toString(), max: 2 });
    let expectedCounts = null;
    if (backup.path.endsWith('.json')) expectedCounts = await restoreJson(drill, backup.path);
    else { expectedCounts = sqlManifest.manifest.counts; await runRestoreProcess(backup.path, scratchName, sourceUrl); }

    const counts = {};
    const existing = await drill.query("SELECT tablename FROM pg_tables WHERE schemaname='public'");
    const available = new Set(existing.rows.map(row => row.tablename));
    for (const table of requiredTables) {
      if (!available.has(table) && addedLaterTables.has(table) && (expectedCounts?.[table] === undefined || expectedCounts?.[table] === 0)) continue;
      if (!available.has(table)) throw new Error(`Restored database is missing ${table}`);
      const result = await drill.query(`SELECT count(*)::integer AS count FROM "${table}"`);
      counts[table] = result.rows[0].count;
      if (expectedCounts && expectedCounts[table] !== undefined && counts[table] !== expectedCounts[table]) throw new Error(`Count mismatch for ${table}: restored ${counts[table]}, expected ${expectedCounts[table]}`);
    }
    const audit = await verifyAudit(drill);
    const workflow = await governedWriteSmoke(drill, scratchName, sourceUrl);
    report = { ok: true, backup: backup.name, format: backup.path.endsWith('.json') ? 'agentguard-json' : 'postgres-sql-gzip', durationMs: Date.now() - startedAt, ...(sqlManifest ? { manifest: path.relative(root, manifestPath(backup.path)) } : {}), restoredCounts: counts, audit, governedWriteSmoke: workflow };
  } catch (error) { primaryError = error; }
  finally {
    if (drill) try { await drill.end(); } catch (error) { cleanupError ||= error; }
    try { await admin.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()', [scratchName]); } catch (error) { cleanupError ||= error; }
    try { await admin.query(`DROP DATABASE IF EXISTS "${scratchName}"`); } catch (error) { cleanupError ||= error; }
    try { await admin.end(); } catch (error) { cleanupError ||= error; }
  }
  if (primaryError || cleanupError) {
    console.error(JSON.stringify({ ok: false, error: primaryError?.message || 'restore drill failed', durationMs: Date.now() - startedAt, cleanup: cleanupError ? { succeeded: false, error: cleanupError.message } : { succeeded: true } }));
    process.exitCode = 1;
    return;
  }
  console.log(JSON.stringify({ ...report, cleanup: { succeeded: true, scratchDatabaseRemoved: true } }));
}

if (require.main === module) runRestoreDrill().catch(error => { console.error(error.message); process.exitCode = 1; });

module.exports = { requiredTables, restoreJson, verifyAudit, discoverBackups, runRestoreDrill };
