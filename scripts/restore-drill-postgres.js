const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { Pool } = require('pg');
const { auditHash } = require('../audit-integrity');

const root = path.join(__dirname, '..');
const backupDirectory = path.join(root, 'backups');
const requiredTables = ['ag_workspaces', 'ag_memberships', 'ag_companies', 'ag_agents', 'ag_policies', 'ag_approvals', 'ag_governed_actions', 'ag_assessments', 'ag_incidents', 'ag_alerts', 'ag_alert_deliveries', 'ag_audit_events'];

function latestBackup() {
  const files = fs.readdirSync(backupDirectory)
    .filter(name => /^postgres-cutover-.*\.json$/.test(name))
    .map(name => ({ name, path: path.join(backupDirectory, name), modified: fs.statSync(path.join(backupDirectory, name)).mtimeMs }))
    .sort((a, b) => b.modified - a.modified);
  if (!files.length) throw new Error('No PostgreSQL JSON backup found; run npm run backup:postgres first');
  return files[0];
}

function connectionUrl(databaseName) {
  const base = process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@127.0.0.1:${process.env.POSTGRES_PORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}`;
  const url = new URL(base);
  url.pathname = `/${databaseName}`;
  return url.toString();
}

async function insertRows(client, table, rows) {
  if (!rows.length) return;
  const columns = Object.keys(rows[0]);
  const names = columns.map(column => `"${column.replaceAll('"', '""')}"`).join(',');
  const batchSize = Math.max(1, Math.floor(60000 / columns.length));
  for (let offset = 0; offset < rows.length; offset += Math.min(batchSize, 250)) {
    const batch = rows.slice(offset, offset + Math.min(batchSize, 250));
    const values = [];
    const tuples = batch.map((row, rowIndex) => {
      const placeholders = columns.map((column, columnIndex) => {
        values.push(row[column]);
        return `$${rowIndex * columns.length + columnIndex + 1}`;
      });
      return `(${placeholders.join(',')})`;
    });
    await client.query(`INSERT INTO "${table}" (${names}) VALUES ${tuples.join(',')}`, values);
  }
}

async function verifyAudit(client) {
  const workspaces = await client.query('SELECT id FROM ag_workspaces ORDER BY id');
  const results = [];
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

(async () => {
  if (!(process.env.AGENTGUARD_STORAGE === 'postgres' || process.env.DATABASE_URL)) throw new Error('PostgreSQL storage is not enabled');
  const backup = latestBackup(), snapshot = JSON.parse(fs.readFileSync(backup.path, 'utf8'));
  for (const table of requiredTables) if (!Array.isArray(snapshot.tables?.[table])) throw new Error(`Backup is missing ${table}; create a fresh backup before the drill`);
  const drillDatabase = `agentguard_restore_${Date.now()}_${randomBytes(3).toString('hex')}`;
  const admin = new Pool({ connectionString: connectionUrl('postgres'), max: 1 });
  let drill;
  try {
    await admin.query(`CREATE DATABASE "${drillDatabase}"`);
    drill = new Pool({ connectionString: connectionUrl(drillDatabase), max: 1 });
    const schema = `${fs.readFileSync(path.join(root, 'infra', 'postgres', 'init.sql'), 'utf8')}\n${fs.readFileSync(path.join(root, 'infra', 'postgres', '002-relational.sql'), 'utf8')}`;
    await drill.query(schema);
    const client = await drill.connect();
    try {
      await client.query('BEGIN');
      for (const table of requiredTables) await insertRows(client, table, snapshot.tables[table]);
      if (Array.isArray(snapshot.tables.agentguard_records)) await insertRows(client, 'agentguard_records', snapshot.tables.agentguard_records);
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
    const counts = {};
    for (const table of requiredTables) {
      const result = await drill.query(`SELECT count(*)::integer AS count FROM "${table}"`);
      counts[table] = result.rows[0].count;
      if (counts[table] !== snapshot.tables[table].length) throw new Error(`Count mismatch for ${table}: restored ${counts[table]}, expected ${snapshot.tables[table].length}`);
    }
    const audit = await verifyAudit(drill);
    console.log(JSON.stringify({ ok: true, backup: backup.name, restoredCounts: counts, audit, isolatedDatabaseRemoved: true }));
  } finally {
    if (drill) await drill.end().catch(() => {});
    await admin.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()', [drillDatabase]).catch(() => {});
    await admin.query(`DROP DATABASE IF EXISTS "${drillDatabase}"`).catch(() => {});
    await admin.end().catch(() => {});
  }
})().catch(error => { console.error(error.message); process.exit(1); });
