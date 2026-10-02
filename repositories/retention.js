const { postgresQuery, postgresTransaction, usePostgres } = require('../storage');
const { appendEventWithClient } = require('./governance');

function hold(row) {
  return {
    id: row.id, workspaceId: row.workspace_id, reason: row.reason,
    caseReference: row.case_reference || null, createdBy: row.created_by,
    createdAt: row.created_at?.toISOString?.() || row.created_at,
    releasedBy: row.released_by || null,
    releasedAt: row.released_at?.toISOString?.() || row.released_at || null,
    releaseReason: row.release_reason || null,
    status: row.released_at ? 'released' : 'active'
  };
}

async function listHolds(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT * FROM ag_audit_legal_holds WHERE workspace_id=$1 ORDER BY (released_at IS NULL) DESC,created_at DESC,id DESC LIMIT 500', [workspaceId]);
  return result.rows.map(hold);
}

async function createHoldWithAudit(item, audit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const result = await client.query(`INSERT INTO ag_audit_legal_holds (workspace_id,id,reason,case_reference,created_by,created_at)
      VALUES ($1,$2,$3,$4,$5,$6::timestamptz) RETURNING *`,
    [item.workspaceId, item.id, item.reason, item.caseReference || null, item.createdBy, item.createdAt]);
    const event = await appendEventWithClient(client, audit);
    if (!event.chainSequence) throw new Error('Legal hold audit event was not inserted');
    return { hold: hold(result.rows[0]), audit: event };
  });
}

async function releaseHoldWithAudit(workspaceId, id, releasedBy, releaseReason, audit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const result = await client.query(`UPDATE ag_audit_legal_holds SET released_by=$3,released_at=now(),release_reason=$4
      WHERE workspace_id=$1 AND id=$2 AND released_at IS NULL RETURNING *`, [workspaceId, id, releasedBy, releaseReason]);
    if (!result.rows.length) return null;
    const event = await appendEventWithClient(client, audit);
    if (!event.chainSequence) throw new Error('Legal hold release audit event was not inserted');
    return { hold: hold(result.rows[0]), audit: event };
  });
}

async function hasActiveHold(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT EXISTS(SELECT 1 FROM ag_audit_legal_holds WHERE workspace_id=$1 AND released_at IS NULL) AS active', [workspaceId]);
  return result.rows[0].active;
}

function policy(row) {
  return { retentionDays: row.audit_retention_days, version: row.retention_version,
    updatedBy: row.retention_updated_by,
    updatedAt: row.retention_updated_at?.toISOString?.() || row.retention_updated_at || null };
}

async function previewRetention(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`SELECT w.audit_retention_days,w.retention_version,w.retention_updated_by,w.retention_updated_at,
    (SELECT count(*)::int FROM ag_audit_legal_holds h WHERE h.workspace_id=w.id AND h.released_at IS NULL) AS active_holds,
    (SELECT count(*)::int FROM ag_audit_events e WHERE e.workspace_id=w.id AND w.audit_retention_days IS NOT NULL
      AND e.created_at < now() - make_interval(days => w.audit_retention_days)) AS candidate_events,
    CASE WHEN w.audit_retention_days IS NULL THEN NULL ELSE now() - make_interval(days => w.audit_retention_days) END AS cutoff_at
    FROM ag_workspaces w WHERE w.id=$1`, [workspaceId]);
  if (!result.rows.length) return null;
  const row = result.rows[0];
  return { ...policy(row), cutoffAt: row.cutoff_at?.toISOString?.() || null,
    candidateEvents: row.candidate_events, activeHolds: row.active_holds,
    cleanupEnabled: false,
    blockers: [...(row.audit_retention_days === null ? ['Retention period is not configured'] : []),
      ...(row.active_holds ? ['Active legal hold protects this workspace'] : []),
      'Verified archive and restore checkpoints are required before cleanup can be enabled'] };
}

async function saveRetentionWithAudit(workspaceId, days, expectedVersion, actor, audit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    const current = await client.query('SELECT retention_version FROM ag_workspaces WHERE id=$1 FOR UPDATE', [workspaceId]);
    if (!current.rows.length) return null;
    if (current.rows[0].retention_version !== expectedVersion) {
      const error = new Error('Retention settings changed; refresh and try again'); error.statusCode = 409; throw error;
    }
    const updated = await client.query(`UPDATE ag_workspaces SET audit_retention_days=$2,retention_updated_by=$3,
      retention_updated_at=now(),retention_version=retention_version+1 WHERE id=$1 RETURNING *`, [workspaceId, days, actor]);
    const event = await appendEventWithClient(client, audit);
    if (!event.chainSequence) throw new Error('Retention settings audit event was not inserted');
    return { policy: policy(updated.rows[0]), audit: event };
  });
}

module.exports = { listHolds, createHoldWithAudit, releaseHoldWithAudit, hasActiveHold, previewRetention, saveRetentionWithAudit };
