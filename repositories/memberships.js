const { postgresQuery, postgresTransaction, usePostgres } = require('../storage');
const { appendEventWithClient } = require('./governance');

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

async function addWithAudit(member, audit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    await client.query("SELECT pg_advisory_xact_lock(hashtext('agentguard-membership'),hashtext($1))", [member.workspaceId]);
    const result = await client.query(`INSERT INTO ag_memberships (id,workspace_id,email,display_name,subject,role,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7::timestamptz,now()),COALESCE($8::timestamptz,now())) RETURNING id,workspace_id,email,display_name,subject,role,created_at,updated_at`, [member.id, member.workspaceId, member.email, member.name || null, member.subject || null, member.role, member.createdAt || null, member.updatedAt || null]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Membership audit event ID already exists; membership was not created'); error.statusCode = 409; throw error; }
    return { member: { ...map(result.rows[0]), invitedBy: member.invitedBy || null }, audit: savedAudit };
  });
}

async function updateRoleWithAudit(id, workspaceId, role, audit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    await client.query("SELECT pg_advisory_xact_lock(hashtext('agentguard-membership'),hashtext($1))", [workspaceId]);
    const current = await client.query('SELECT id,workspace_id,email,display_name,subject,role,created_at,updated_at FROM ag_memberships WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [workspaceId, id]);
    if (!current.rows[0]) return null;
    if (current.rows[0].role === 'owner' && role !== 'owner') {
      const owners = await client.query("SELECT count(*)::int AS count FROM ag_memberships WHERE workspace_id=$1 AND role='owner'", [workspaceId]);
      if (owners.rows[0].count <= 1) { const error = new Error('Assign another owner before changing the last owner'); error.statusCode = 409; throw error; }
    }
    const result = await client.query('UPDATE ag_memberships SET role=$3,updated_at=now() WHERE workspace_id=$1 AND id=$2 RETURNING id,workspace_id,email,display_name,subject,role,created_at,updated_at', [workspaceId, id, role]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Membership audit event ID already exists; role change was not committed'); error.statusCode = 409; throw error; }
    return { member: map(result.rows[0]), audit: savedAudit };
  });
}

async function removeWithAudit(id, workspaceId, audit) {
  if (!usePostgres) return undefined;
  return postgresTransaction(async client => {
    await client.query("SELECT pg_advisory_xact_lock(hashtext('agentguard-membership'),hashtext($1))", [workspaceId]);
    const current = await client.query('SELECT id,workspace_id,email,display_name,subject,role,created_at,updated_at FROM ag_memberships WHERE workspace_id=$1 AND id=$2 FOR UPDATE', [workspaceId, id]);
    if (!current.rows[0]) return null;
    if (current.rows[0].role === 'owner') {
      const owners = await client.query("SELECT count(*)::int AS count FROM ag_memberships WHERE workspace_id=$1 AND role='owner'", [workspaceId]);
      if (owners.rows[0].count <= 1) { const error = new Error('Assign another owner before removing the last owner'); error.statusCode = 409; throw error; }
    }
    await client.query('DELETE FROM ag_memberships WHERE workspace_id=$1 AND id=$2', [workspaceId, id]);
    const savedAudit = await appendEventWithClient(client, audit);
    if (!savedAudit.chainSequence) { const error = new Error('Membership audit event ID already exists; removal was not committed'); error.statusCode = 409; throw error; }
    return { member: map(current.rows[0]), audit: savedAudit };
  });
}

module.exports = { list, create, updateRole, remove, addWithAudit, updateRoleWithAudit, removeWithAudit };
