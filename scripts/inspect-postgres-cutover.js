const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@${process.env.PGHOST || '127.0.0.1'}:${process.env.POSTGRES_PORT || process.env.PGPORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}`;

// These definitions are read-only identity/payload projections for each
// legacy collection. They are intentionally static, not caller-controlled.
const inventories = [
  { table: 'ag_workspaces', collection: 'workspaces', relationKey: 'jsonb_build_array(r.id)::text', legacyKey: 'jsonb_build_array(l.record_id)::text', relationPayload: "jsonb_build_object('name',r.name)", legacyPayload: "jsonb_build_object('name',l.payload->>'name')" },
  { table: 'ag_memberships', collection: 'memberships', relationKey: 'jsonb_build_array(r.workspace_id,r.id)::text', legacyKey: 'jsonb_build_array(l.workspace_id,l.record_id)::text', relationPayload: "jsonb_build_object('email',r.email,'name',COALESCE(r.display_name,r.email),'subject',r.subject,'role',r.role)", legacyPayload: "jsonb_build_object('email',l.payload->>'email','name',COALESCE(l.payload->>'name',l.payload->>'email'),'subject',l.payload->>'subject','role',l.payload->>'role')" },
  { table: 'ag_companies', collection: 'companies', relationKey: 'jsonb_build_array(r.workspace_id,r.id)::text', legacyKey: 'jsonb_build_array(l.workspace_id,l.record_id)::text', relationPayload: 'r.payload', legacyPayload: 'l.payload' },
  { table: 'ag_agents', collection: 'agents', relationKey: 'jsonb_build_array(r.workspace_id,r.id)::text', legacyKey: 'jsonb_build_array(l.workspace_id,l.record_id)::text', relationPayload: 'r.payload', legacyPayload: 'l.payload' },
  { table: 'ag_policies', collection: 'policies', relationKey: 'jsonb_build_array(r.workspace_id,r.id)::text', legacyKey: 'jsonb_build_array(l.workspace_id,l.record_id)::text', relationPayload: 'r.payload', legacyPayload: 'l.payload' },
  { table: 'ag_approvals', collection: 'approvals', relationKey: 'jsonb_build_array(r.workspace_id,r.id)::text', legacyKey: 'jsonb_build_array(l.workspace_id,l.record_id)::text', relationPayload: 'r.payload', legacyPayload: 'l.payload' },
  { table: 'ag_assessments', collection: 'assessments', relationKey: 'jsonb_build_array(r.workspace_id,r.id)::text', legacyKey: 'jsonb_build_array(l.workspace_id,l.record_id)::text', relationPayload: 'r.payload', legacyPayload: 'l.payload' },
  { table: 'ag_incidents', collection: 'incidents', relationKey: 'jsonb_build_array(r.workspace_id,r.id)::text', legacyKey: 'jsonb_build_array(l.workspace_id,l.record_id)::text', relationPayload: 'r.payload', legacyPayload: 'l.payload' },
  { table: 'ag_audit_events', collection: 'events', relationKey: 'jsonb_build_array(r.workspace_id,r.id)::text', legacyKey: 'jsonb_build_array(l.workspace_id,l.record_id)::text', relationPayload: 'r.payload', legacyPayload: 'l.payload' }
];

async function inspect(client) {
  const tables = await client.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name = ANY($1::text[])`, [[...inventories.map(item => item.table), 'agentguard_records']]);
  const available = new Set(tables.rows.map(row => row.table_name));
  const missingRelationalTables = inventories.map(item => item.table).filter(name => !available.has(name));
  const legacyTablePresent = available.has('agentguard_records');
  const rows = [];
  if (!legacyTablePresent) return {
    readOnly: true,
    startupSource: 'relational-tables',
    missingRelationalTables,
    legacyTablePresent: false,
    collections: rows,
    relationalSchemaReady: missingRelationalTables.length === 0,
    mirrorInSync: null,
    dataParityCandidate: false,
    note: 'The legacy table is absent, so there is no mirror to compare. This report does not verify code paths or authorize schema changes.'
  };
  for (const item of inventories) {
    if (!available.has(item.table)) { rows.push({ collection: item.collection, relationalTable: item.table, missing: true }); continue; }
    const projection = item.relationPayload ? `, ${item.relationPayload} AS payload` : '';
    const legacyProjection = item.legacyPayload ? `, ${item.legacyPayload} AS payload` : '';
    const result = await client.query(`WITH relational AS (
        SELECT ${item.relationKey} AS key${projection} FROM ${item.table} r
      ), legacy AS (
        SELECT ${item.legacyKey} AS key${legacyProjection} FROM agentguard_records l WHERE l.collection=$1
      ), joined AS (
        SELECT relational.key AS r_key, legacy.key AS l_key${item.relationPayload ? ', relational.payload AS r_payload, legacy.payload AS l_payload' : ''}
        FROM relational FULL OUTER JOIN legacy ON legacy.key=relational.key
      ) SELECT count(*) FILTER (WHERE r_key IS NULL)::int AS "legacyOnly",
          count(*) FILTER (WHERE l_key IS NULL)::int AS "relationalOnly",
          ${item.relationPayload ? 'count(*) FILTER (WHERE r_key IS NOT NULL AND l_key IS NOT NULL AND r_payload IS DISTINCT FROM l_payload)::int' : '0::int'} AS "payloadMismatches"
          , COALESCE((SELECT jsonb_agg(sample.key) FROM (SELECT l_key AS key FROM joined WHERE r_key IS NULL ORDER BY l_key LIMIT 5) sample),'[]'::jsonb) AS "legacyOnlySamples"
          , COALESCE((SELECT jsonb_agg(sample.key) FROM (SELECT r_key AS key FROM joined WHERE l_key IS NULL ORDER BY r_key LIMIT 5) sample),'[]'::jsonb) AS "relationalOnlySamples"
          ${item.relationPayload ? ', COALESCE((SELECT jsonb_agg(sample.key) FROM (SELECT r_key AS key FROM joined WHERE r_key IS NOT NULL AND l_key IS NOT NULL AND r_payload IS DISTINCT FROM l_payload ORDER BY r_key LIMIT 5) sample),\'[]\'::jsonb) AS "payloadMismatchSamples"' : ", '[]'::jsonb AS \"payloadMismatchSamples\""}
        FROM joined`, [item.collection]);
    const counts = await client.query(`SELECT (SELECT count(*)::int FROM ${item.table}) AS "relationalCount",
      (SELECT count(*)::int FROM agentguard_records WHERE collection=$1) AS "legacyCount"`, [item.collection]);
    rows.push({ collection: item.collection, relationalTable: item.table, ...counts.rows[0], ...result.rows[0] });
  }
  const relationalSchemaReady = missingRelationalTables.length === 0;
  const mirrorInSync = relationalSchemaReady && rows.every(row => !row.missing && row.legacyOnly === 0 && row.relationalOnly === 0 && row.payloadMismatches === 0);
  const workspace = rows.find(row => row.collection === 'workspaces');
  const startupSource = workspace?.relationalCount > 0 ? 'relational-tables' : 'compatibility-or-local-bootstrap';
  return { readOnly: true, startupSource, missingRelationalTables, legacyTablePresent, relationalSchemaReady, collections: rows, mirrorInSync, dataParityCandidate: mirrorInSync, note: 'Data parity is diagnostic only; it does not verify runtime code paths or authorize deleting backup or legacy tables.' };
}

async function main() {
  const pool = new Pool({ connectionString, max: 1 });
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN READ ONLY');
      const report = await inspect(client);
      await client.query('ROLLBACK');
      console.log(JSON.stringify(report, null, 2));
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally { client.release(); }
  } finally { await pool.end(); }
}

if (require.main === module) main().catch(error => { console.error(`Read-only cutover inspection failed: ${error.message}`); process.exitCode = 1; });
module.exports = { inspect };
