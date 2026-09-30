const { postgresQuery, usePostgres } = require('../storage');

function map(row) {
  return { id: row.id, workspaceId: row.workspace_id, email: row.email, name: row.display_name || row.email, subject: row.subject || null, role: row.role, createdAt: row.created_at?.toISOString?.() || row.created_at, updatedAt: row.updated_at?.toISOString?.() || row.updated_at, source: 'postgres' };
}

async function list(workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('SELECT id, workspace_id, email, display_name, subject, role, created_at, updated_at FROM ag_memberships WHERE workspace_id=$1 ORDER BY email', [workspaceId]);
  return result.rows.map(map);
}

async function create(member) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`INSERT INTO ag_memberships (id, workspace_id, email, display_name, subject, role, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,now(),now()) RETURNING id, workspace_id, email, display_name, subject, role, created_at, updated_at`, [member.id, member.workspaceId, member.email, member.name || null, member.subject || null, member.role]);
  return map(result.rows[0]);
}

async function updateRole(id, workspaceId, role) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery(`UPDATE ag_memberships SET role=$3,updated_at=now() WHERE id=$1 AND workspace_id=$2 RETURNING id, workspace_id, email, display_name, subject, role, created_at, updated_at`, [id, workspaceId, role]);
  return result.rows[0] ? map(result.rows[0]) : null;
}

async function remove(id, workspaceId) {
  if (!usePostgres) return undefined;
  const result = await postgresQuery('DELETE FROM ag_memberships WHERE id=$1 AND workspace_id=$2 RETURNING id', [id, workspaceId]);
  return Boolean(result.rowCount);
}

module.exports = { list, create, updateRole, remove };
