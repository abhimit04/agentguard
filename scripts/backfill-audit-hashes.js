const { createHash } = require('node:crypto');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@127.0.0.1:${process.env.POSTGRES_PORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}` });

async function main() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('ALTER TABLE ag_audit_events ADD COLUMN IF NOT EXISTS previous_hash text; ALTER TABLE ag_audit_events ADD COLUMN IF NOT EXISTS event_hash text;');
    const workspaces = await client.query('SELECT DISTINCT workspace_id FROM ag_audit_events ORDER BY workspace_id');
    let updated = 0;
    for (const { workspace_id: workspaceId } of workspaces.rows) {
      const events = await client.query('SELECT id,agent_id,kind,event_type,actor,message,created_at,payload FROM ag_audit_events WHERE workspace_id=$1 ORDER BY created_at ASC,id ASC', [workspaceId]);
      let previousHash = null;
      for (const item of events.rows) {
        const canonical = JSON.stringify({ workspaceId, id: item.id, agentId: item.agent_id || null, kind: item.kind || 'action', eventType: item.event_type || null, actor: item.actor || 'system', message: item.message || 'AgentGuard event', createdAt: item.created_at?.toISOString?.() || item.created_at, payload: item.payload });
        const eventHash = createHash('sha256').update(`${previousHash || ''}:${canonical}`).digest('hex');
        await client.query('UPDATE ag_audit_events SET previous_hash=$3,event_hash=$4 WHERE workspace_id=$1 AND id=$2', [workspaceId, item.id, previousHash, eventHash]);
        previousHash = eventHash;
        updated += 1;
      }
    }
    await client.query('COMMIT');
    console.log(JSON.stringify({ workspaces: workspaces.rowCount, hashedEvents: updated }));
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); await pool.end(); }
}
main().catch(error => { console.error(error.message); process.exit(1); });
