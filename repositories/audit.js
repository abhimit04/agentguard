const { postgresQuery, usePostgres } = require('../storage');

function eventRow(row) {
  return {
    ...row.payload,
    workspaceId: row.workspace_id,
    id: row.id,
    agentId: row.agent_id || null,
    kind: row.kind,
    eventType: row.event_type || null,
    actor: row.actor,
    message: row.message,
    createdAt: row.created_at?.toISOString?.() || row.created_at,
    previousHash: row.previous_hash || null,
    eventHash: row.event_hash || null,
    chainSequence: Number(row.chain_sequence)
  };
}

async function bounds(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`SELECT COALESCE(MAX(chain_sequence),0)::bigint AS upper_sequence,
      COUNT(*)::bigint AS event_count,
      (SELECT event_hash FROM ag_audit_events WHERE workspace_id=$1 ORDER BY chain_sequence DESC LIMIT 1) AS head_hash
    FROM ag_audit_events WHERE workspace_id=$1`, [workspaceId]);
  const row = result.rows[0];
  return { upperSequence: Number(row.upper_sequence), eventCount: Number(row.event_count), headHash: row.head_hash || null };
}

async function page(workspaceId, afterSequence, upperSequence, limit = 500) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`SELECT chain_sequence,workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,payload
    FROM ag_audit_events WHERE workspace_id=$1 AND chain_sequence>$2 AND chain_sequence<=$3
    ORDER BY chain_sequence ASC LIMIT $4`, [workspaceId, afterSequence, upperSequence, limit]);
  return result.rows.map(row => ({
    ...row,
    chain_sequence: Number(row.chain_sequence),
    payload: row.payload
  }));
}

async function pageOlder(workspaceId, beforeSequence, upperSequence, limit = 250) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`SELECT chain_sequence,workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,payload
    FROM ag_audit_events WHERE workspace_id=$1 AND chain_sequence<$2 AND chain_sequence<=$3
      AND COALESCE(event_type,'') <> 'heartbeat' AND message !~* 'heartbeat|agent is online'
    ORDER BY chain_sequence DESC LIMIT $4`, [workspaceId, beforeSequence, upperSequence, limit]);
  return result.rows.map(row => ({ ...row, chain_sequence: Number(row.chain_sequence) }));
}

async function range(workspaceId, fromSequence, toSequence, limit = 10001) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`SELECT chain_sequence,workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,payload
    FROM ag_audit_events WHERE workspace_id=$1 AND chain_sequence>=$2 AND chain_sequence<=$3
    ORDER BY chain_sequence ASC LIMIT $4`, [workspaceId, fromSequence, toSequence, limit]);
  return result.rows.map(row => ({ ...row, chain_sequence: Number(row.chain_sequence) }));
}

async function previousHash(workspaceId, sequence) {
  if (!usePostgres) return undefined;
  if (sequence <= 0) return null;
  const result = await postgresQuery('SELECT event_hash FROM ag_audit_events WHERE workspace_id=$1 AND chain_sequence<$2 ORDER BY chain_sequence DESC LIMIT 1', [workspaceId, sequence]);
  return result.rows[0]?.event_hash || null;
}

module.exports = { bounds, page, pageOlder, range, previousHash, eventRow };
