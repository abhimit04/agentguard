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

module.exports = { stableStringify, canonicalAuditRecord, auditHash };
