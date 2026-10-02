const { createHash } = require('node:crypto');

function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

function canonicalAuditRecord(item, workspaceId = item.workspaceId || 'default') {
  return stableStringify({
    workspaceId,
    id: item.id,
    agentId: item.agentId || null,
    kind: item.kind || 'action',
    eventType: item.eventType || null,
    actor: item.actor || 'system',
    message: item.message || 'AgentGuard event',
    createdAt: item.createdAt || null,
    payload: item
  });
}

function auditHash(previousHash, item, workspaceId) {
  return createHash('sha256').update(`${previousHash || ''}:${canonicalAuditRecord(item, workspaceId)}`).digest('hex');
}

function verifyAuditPage(state, rows) {
  const next = { ...state };
  for (const row of rows) {
    const sequence = Number(row.chain_sequence ?? row.chainSequence);
    const workspaceId = row.workspace_id || row.workspaceId || next.workspaceId;
    const payload = row.payload;
    if (next.workspaceId && workspaceId !== next.workspaceId) {
      return { state: next, failure: { sequence, eventId: row.id, reason: 'workspace mismatch' } };
    }
    if (row.previous_hash !== undefined && row.previous_hash !== next.previousHash) {
      return { state: next, failure: { sequence, eventId: row.id, reason: 'previous_hash mismatch' } };
    }
    const expected = auditHash(next.previousHash, payload, workspaceId);
    if (row.event_hash !== expected) return { state: next, failure: { sequence, eventId: row.id, reason: 'event_hash mismatch' } };
    if (next.startSequence === null) next.startSequence = sequence;
    next.endSequence = sequence;
    next.previousHash = row.event_hash;
    next.headHash = row.event_hash;
    next.checked++;
  }
  return { state: next, failure: null };
}

module.exports = { stableStringify, canonicalAuditRecord, auditHash, verifyAuditPage };
