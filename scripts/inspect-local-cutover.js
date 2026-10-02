const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { Pool } = require('pg');

const collections = ['workspaces', 'memberships', 'companies', 'agents', 'policies', 'approvals', 'assessments', 'incidents', 'events'];
const sqlitePath = path.resolve(process.env.AGENTGUARD_SQLITE_PATH || path.join(__dirname, '..', 'agentguard.sqlite'));
const jsonPath = path.resolve(process.env.AGENTGUARD_JSON_PATH || path.join(__dirname, '..', 'data.json'));
const connectionString = process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@${process.env.PGHOST || '127.0.0.1'}:${process.env.POSTGRES_PORT || process.env.PGPORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}`;

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function indexStore(store = {}) {
  const indexed = new Map();
  for (const collection of collections) {
    const rows = Array.isArray(store[collection]) ? store[collection] : [];
    for (const row of rows) {
      if (!row || row.id === undefined || row.id === null) continue;
      const key = `${row.workspaceId || 'default'}\u0000${String(row.id)}`;
      indexed.set(`${collection}\u0000${key}`, canonical(row));
    }
  }
  return indexed;
}

function compareStores(leftStore, rightStore, [leftName = 'sqlite', rightName = 'json'] = []) {
  const left = indexStore(leftStore);
  const right = indexStore(rightStore);
  return collections.map(collection => {
    const prefix = `${collection}\u0000`;
    const leftRows = new Map([...left].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => [key, value]));
    const rightRows = new Map([...right].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => [key, value]));
    let leftOnly = 0; let rightOnly = 0; let payloadMismatches = 0;
    for (const [key, value] of leftRows) {
      if (!rightRows.has(key)) leftOnly++;
      else if (rightRows.get(key) !== value) payloadMismatches++;
    }
    for (const key of rightRows.keys()) if (!leftRows.has(key)) rightOnly++;
    return { collection, [`${leftName}Count`]: leftRows.size, [`${rightName}Count`]: rightRows.size, [`${leftName}Only`]: leftOnly, [`${rightName}Only`]: rightOnly, payloadMismatches };
  });
}

function summarizeAuditPair(leftEvents = [], rightEvents = [], [leftName = 'left', rightName = 'right'] = []) {
  const keyOf = event => `${event.workspaceId || 'default'}\u0000${String(event.id)}`;
  const left = new Map(leftEvents.filter(event => event?.id !== undefined && event?.id !== null).map(event => [keyOf(event), event]));
  const right = new Map(rightEvents.filter(event => event?.id !== undefined && event?.id !== null).map(event => [keyOf(event), event]));
  let leftOnly = 0; let rightOnly = 0; let shared = 0; let payloadMismatches = 0;
  let comparableStoredHashes = 0; let matchingStoredHashes = 0; let mismatchingStoredHashes = 0;
  for (const [key, event] of left) {
    const other = right.get(key);
    if (!other) { leftOnly++; continue; }
    shared++;
    if (canonical(event) !== canonical(other)) payloadMismatches++;
    if (event.eventHash && other.eventHash) {
      comparableStoredHashes++;
      if (event.eventHash === other.eventHash) matchingStoredHashes++;
      else mismatchingStoredHashes++;
    }
  }
  for (const key of right.keys()) if (!left.has(key)) rightOnly++;
  const coverage = events => ({
    events: events.length,
    withEventHash: events.filter(event => Boolean(event?.eventHash)).length,
    withPreviousHash: events.filter(event => Boolean(event?.previousHash)).length,
    withChainSequence: events.filter(event => Number.isFinite(Number(event?.chainSequence)) && Number(event?.chainSequence) > 0).length
  });
  return {
    [`${leftName}Events`]: left.size,
    [`${rightName}Events`]: right.size,
    [`${leftName}Only`]: leftOnly,
    [`${rightName}Only`]: rightOnly,
    shared,
    payloadMismatches,
    storedHashesComparable: comparableStoredHashes,
    storedHashesMatch: matchingStoredHashes,
    storedHashesDiffer: mismatchingStoredHashes,
    hashCoverage: { [leftName]: coverage(leftEvents), [rightName]: coverage(rightEvents) },
    safeForAutomaticMerge: leftOnly === 0 && rightOnly === 0 && payloadMismatches === 0 && mismatchingStoredHashes === 0
  };
}

function readSqliteStore(filename) {
  if (!fs.existsSync(filename)) return null;
  const database = new DatabaseSync(filename, { readOnly: true });
  try {
    const table = database.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='agentguard_store'").get();
    if (!table) return null;
    const row = database.prepare('SELECT payload FROM agentguard_store WHERE id=1').get();
    return row ? JSON.parse(row.payload) : null;
  } finally { database.close(); }
}

function readJsonStore(filename) {
  if (!fs.existsSync(filename)) return null;
  return JSON.parse(fs.readFileSync(filename, 'utf8'));
}

async function readRelationalStore(client) {
  const iso = value => value?.toISOString?.() || value || null;
  const workspaces = await client.query('SELECT id,name,created_at,updated_at FROM ag_workspaces');
  const memberships = await client.query('SELECT id,workspace_id,email,display_name,subject,role,created_at,updated_at FROM ag_memberships');
  const companies = await client.query('SELECT workspace_id,id,name,gateway_credential_hash,created_at,payload FROM ag_companies');
  const agents = await client.query('SELECT workspace_id,id,company_id,name,team,status,runtime_status,parent_id,credential_hash,last_seen_at,created_at,payload FROM ag_agents');
  const policies = await client.query('SELECT workspace_id,id,agent_id,name,effect,enabled,version,priority,created_at,updated_at,payload FROM ag_policies');
  const approvals = await client.query('SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload FROM ag_approvals');
  const assessments = await client.query('SELECT workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload FROM ag_assessments');
  const incidents = await client.query('SELECT workspace_id,id,agent_id,status,severity,title,owner,source_event_id,created_at,updated_at,resolved_at,payload FROM ag_incidents');
  const events = await client.query('SELECT workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,chain_sequence,payload FROM ag_audit_events');
  return {
    workspaces: workspaces.rows.map(row => ({ id: row.id, name: row.name, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) })),
    memberships: memberships.rows.map(row => ({ id: row.id, workspaceId: row.workspace_id, email: row.email, name: row.display_name || row.email, subject: row.subject || null, role: row.role, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) })),
    companies: companies.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, name: row.name, gatewayCredentialHash: row.gateway_credential_hash || row.payload?.gatewayCredentialHash, createdAt: iso(row.created_at) })),
    agents: agents.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, companyId: row.company_id, name: row.name, team: row.team, status: row.status, runtimeStatus: row.runtime_status, parentId: row.parent_id, credentialHash: row.credential_hash || row.payload?.credentialHash, lastSeenAt: iso(row.last_seen_at), createdAt: iso(row.created_at) })),
    policies: policies.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, name: row.name, effect: row.effect, enabled: row.enabled, version: row.version, priority: row.priority, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) })),
    approvals: approvals.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, policyId: row.policy_id || null, status: row.status, action: row.action, actionRef: row.action_ref || null, createdAt: iso(row.created_at), decidedAt: iso(row.decided_at) })),
    assessments: assessments.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, status: row.status, owner: row.owner || null, reviewDueAt: iso(row.review_due_at), createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) })),
    incidents: incidents.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id || null, status: row.status, severity: row.severity, title: row.title, owner: row.owner || null, sourceEventId: row.source_event_id || null, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at), resolvedAt: iso(row.resolved_at) })),
    events: events.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id || null, kind: row.kind, eventType: row.event_type || null, actor: row.actor, message: row.message, createdAt: iso(row.created_at), previousHash: row.previous_hash || null, eventHash: row.event_hash || null, chainSequence: Number(row.chain_sequence) || null }))
  };
}

async function main() {
  const sqliteStore = readSqliteStore(sqlitePath);
  const jsonStore = readJsonStore(jsonPath);
  const pool = new Pool({ connectionString, max: 1 });
  try {
    const client = await pool.connect();
    let postgresStore;
    try {
      await client.query('BEGIN READ ONLY');
      postgresStore = await readRelationalStore(client);
      await client.query('ROLLBACK');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally { client.release(); }
    console.log(JSON.stringify({
      readOnly: true,
      sqliteFile: path.basename(sqlitePath),
      sqliteStorePresent: Boolean(sqliteStore),
      jsonFile: path.basename(jsonPath),
      jsonStorePresent: Boolean(jsonStore),
      postgresSource: 'relational-tables',
      comparisons: {
        sqliteVsJson: compareStores(sqliteStore, jsonStore),
        postgresVsSqlite: compareStores(postgresStore, sqliteStore, ['postgres', 'sqlite']),
        postgresVsJson: compareStores(postgresStore, jsonStore, ['postgres', 'json'])
      },
      auditEventReconciliation: {
        postgresVsSqlite: summarizeAuditPair(postgresStore.events, sqliteStore?.events || [], ['postgres', 'sqlite']),
        postgresVsJson: summarizeAuditPair(postgresStore.events, jsonStore?.events || [], ['postgres', 'json']),
        sqliteVsJson: summarizeAuditPair(sqliteStore?.events || [], jsonStore?.events || [], ['sqlite', 'json'])
      },
      payloadsPrinted: false,
      note: 'Counts and differences are diagnostic only. They do not decide which snapshot is authoritative or perform migration.'
    }, null, 2));
  } finally { await pool.end(); }
}

if (require.main === module) {
  main().catch(error => { console.error(`Local cutover inspection failed: ${error.message}`); process.exitCode = 1; });
}

module.exports = { compareStores, summarizeAuditPair, readRelationalStore };
