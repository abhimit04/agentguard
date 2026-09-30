const fs = require('node:fs');
const path = require('node:path');
const { initializeStore, postgresQuery, usePostgres } = require('../storage');

const tables = ['ag_workspaces', 'ag_memberships', 'ag_companies', 'ag_agents', 'ag_policies', 'ag_approvals', 'ag_governed_actions', 'ag_assessments', 'ag_incidents', 'ag_alerts', 'ag_alert_deliveries', 'ag_audit_events', 'agentguard_records'];

(async () => {
  if (!usePostgres) throw new Error('PostgreSQL storage is not enabled');
  await initializeStore();
  const snapshot = { createdAt: new Date().toISOString(), schema: 12, tables: {} };
  for (const table of tables) {
    const result = await postgresQuery(`SELECT * FROM ${table}`);
    snapshot.tables[table] = result.rows;
  }
  const stamp = snapshot.createdAt.replace(/[:.]/g, '-');
  const directory = path.join(__dirname, '..', 'backups');
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, `postgres-cutover-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(snapshot, null, 2));
  console.log(JSON.stringify({ file, counts: Object.fromEntries(tables.map(table => [table, snapshot.tables[table].length])) }));
  process.exit(0);
})().catch(error => { console.error(error.message); process.exit(1); });
