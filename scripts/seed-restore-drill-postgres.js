const { randomUUID } = require('node:crypto');

async function main() {
  if (process.env.AGENTGUARD_STORAGE !== 'postgres' || !process.env.DATABASE_URL) throw new Error('Synthetic restore fixtures require an explicit PostgreSQL DATABASE_URL');
  const storage = require('../storage');
  const governance = require('../repositories/governance');
  try {
    await storage.initializeStore();
    await storage.postgresQuery("INSERT INTO ag_workspaces(id,name) VALUES ('ci-restore-workspace','CI restore drill workspace') ON CONFLICT (id) DO NOTHING");
    await storage.postgresQuery("INSERT INTO ag_companies(workspace_id,id,name,payload) VALUES ('ci-restore-workspace','ci-restore-company','CI restore drill company','{}') ON CONFLICT (workspace_id,id) DO NOTHING");
    await governance.appendEvent({
      id: randomUUID(), workspaceId: 'ci-restore-workspace', agentId: null,
      kind: 'action', eventType: 'ci.restore_fixture', actor: 'ci',
      message: 'Synthetic audit event for PostgreSQL restore verification',
      createdAt: new Date().toISOString(), fixture: true,
    });
    await governance.flushAudit();
    console.log('Synthetic workspace, company, and hash-chained audit event are ready for pg_dump.');
  } finally {
    await storage.closePostgres();
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
