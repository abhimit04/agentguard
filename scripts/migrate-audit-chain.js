const { initializeStore, postgresTransaction, usePostgres } = require('../storage');
const { auditHash } = require('../audit-integrity');

(async () => {
  if (!usePostgres) throw new Error('PostgreSQL storage is not enabled');
  await initializeStore();
  const results = await postgresTransaction(async client => {
    const workspaces = await client.query('SELECT id FROM ag_workspaces ORDER BY id FOR UPDATE');
    for (const workspace of workspaces.rows) await client.query(`SELECT pg_advisory_xact_lock(hashtext('agentguard-audit'), hashtext($1))`, [workspace.id]);
    const rows = await client.query('SELECT workspace_id,id,payload FROM ag_audit_events ORDER BY workspace_id,created_at,id FOR UPDATE');
    const max = await client.query('SELECT COALESCE(max(chain_sequence),0)::bigint AS value FROM ag_audit_events');
    const offset = BigInt(max.rows[0].value) + BigInt(rows.rowCount) + 1n;
    await client.query('UPDATE ag_audit_events SET chain_sequence=chain_sequence+$1', [offset.toString()]);
    const previousByWorkspace = new Map(); const counts = new Map();
    for (let index = 0; index < rows.rows.length; index++) {
      const row = rows.rows[index]; const previousHash = previousByWorkspace.get(row.workspace_id) || null;
      const eventHash = auditHash(previousHash, row.payload, row.workspace_id);
      await client.query('UPDATE ag_audit_events SET chain_sequence=$3,previous_hash=$4,event_hash=$5 WHERE workspace_id=$1 AND id=$2', [row.workspace_id, row.id, index + 1, previousHash, eventHash]);
      previousByWorkspace.set(row.workspace_id, eventHash); counts.set(row.workspace_id, (counts.get(row.workspace_id) || 0) + 1);
    }
    return workspaces.rows.map(workspace => ({ workspaceId: workspace.id, rehashed: counts.get(workspace.id) || 0 }));
  });
  console.log(JSON.stringify({ ok: true, results }));
  process.exit(0);
})().catch(error => { console.error(error.message); process.exit(1); });
