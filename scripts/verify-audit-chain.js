const { initializeStore, postgresQuery, usePostgres } = require('../storage');
const { auditHash } = require('../audit-integrity');

async function verifyAuditChain(workspaceId) {
  const result = await postgresQuery(`SELECT chain_sequence,workspace_id,id,agent_id,kind,event_type,actor,message,previous_hash,event_hash,payload
    FROM ag_audit_events WHERE workspace_id=$1 ORDER BY chain_sequence ASC`, [workspaceId]);
  let previousHash = null;
  for (const row of result.rows) {
    if (row.previous_hash !== previousHash) return { ok: false, checked: result.rows.indexOf(row), eventId: row.id, reason: 'previous_hash mismatch' };
    const expected = auditHash(previousHash, row.payload, row.workspace_id);
    if (row.event_hash !== expected) return { ok: false, checked: result.rows.indexOf(row), eventId: row.id, reason: 'event_hash mismatch' };
    previousHash = row.event_hash;
  }
  return { ok: true, checked: result.rowCount, head: previousHash };
}

if (require.main === module) {
  (async () => {
    if (!usePostgres) throw new Error('PostgreSQL storage is not enabled');
    await initializeStore();
    const workspaces = await postgresQuery('SELECT id FROM ag_workspaces ORDER BY id');
    const results = [];
    for (const workspace of workspaces.rows) results.push({ workspaceId: workspace.id, ...(await verifyAuditChain(workspace.id)) });
    const failed = results.find(result => !result.ok);
    console.log(JSON.stringify({ ok: !failed, results }));
    process.exit(failed ? 1 : 0);
  })().catch(error => { console.error(error.message); process.exit(1); });
}

module.exports = { verifyAuditChain };
