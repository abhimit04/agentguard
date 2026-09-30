const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');

const dataFile = path.join(__dirname, 'data.json');
const databaseFile = path.join(__dirname, 'agentguard.sqlite');
const relationalSchemaFile = path.join(__dirname, 'infra', 'postgres', '002-relational.sql');
const schemaVersion = 13;
const seed = { schemaVersion, workspaces: [{ id: 'default', name: 'AgentGuard Workspace' }], memberships: [], companies: [{ id: 'default', workspaceId: 'default', name: 'Default workspace' }], agents: [], policies: [], approvals: [], assessments: [], incidents: [], alerts: [], events: [] };
const collections = ['workspaces', 'memberships', 'companies', 'agents', 'policies', 'approvals', 'assessments', 'incidents', 'events'];
const usePostgres = process.env.AGENTGUARD_STORAGE
  ? process.env.AGENTGUARD_STORAGE === 'postgres'
  : Boolean(process.env.DATABASE_URL);
const pool = usePostgres ? new Pool(process.env.DATABASE_URL ? { connectionString: process.env.DATABASE_URL } : {
  host: process.env.PGHOST || '127.0.0.1',
  port: Number(process.env.PGPORT || process.env.POSTGRES_PORT || 5432),
  database: process.env.PGDATABASE || process.env.POSTGRES_DB || 'agentguard',
  user: process.env.PGUSER || process.env.POSTGRES_USER || 'agentguard',
  password: process.env.PGPASSWORD || process.env.POSTGRES_PASSWORD || '',
}) : null;
let cachedStore = null;

const database = usePostgres ? null : new (require('node:sqlite').DatabaseSync)(databaseFile);
if (database) database.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS agentguard_store (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);

function normalize(store = {}) {
  store.schemaVersion = schemaVersion;
  store.workspaces = Array.isArray(store.workspaces) && store.workspaces.length ? store.workspaces : structuredClone(seed.workspaces);
  store.memberships = Array.isArray(store.memberships) ? store.memberships : [];
  store.companies = Array.isArray(store.companies) && store.companies.length ? store.companies : structuredClone(seed.companies);
  store.agents = Array.isArray(store.agents) ? store.agents : [];
  store.policies = Array.isArray(store.policies) ? store.policies : [];
  store.approvals = Array.isArray(store.approvals) ? store.approvals : [];
  store.assessments = Array.isArray(store.assessments) ? store.assessments : [];
  store.incidents = Array.isArray(store.incidents) ? store.incidents : [];
  store.alerts = Array.isArray(store.alerts) ? store.alerts : [];
  store.events = Array.isArray(store.events) ? store.events : [];
  for (const collection of [store.memberships, store.companies, store.agents, store.policies, store.approvals, store.assessments, store.incidents, store.alerts, store.events]) for (const item of collection) item.workspaceId = item.workspaceId || 'default';
  for (const agent of store.agents) agent.companyId = agent.companyId || 'default';
  return store;
}

function hasApplicationData(store) {
  if (!store) return false;
  return ['memberships', 'agents', 'policies', 'approvals', 'assessments', 'incidents', 'events'].some(key => Array.isArray(store[key]) && store[key].length > 0)
    || (Array.isArray(store.companies) && store.companies.some(item => item.id !== 'default' || item.workspaceId !== 'default' || item.name !== 'Default workspace' || Object.keys(item).some(key => !['id', 'workspaceId', 'name'].includes(key))))
    || (Array.isArray(store.workspaces) && store.workspaces.some(item => item.id !== 'default' || item.name !== 'AgentGuard Workspace'));
}

function readLocalStoreForMigrationCheck() {
  const stores = [];
  if (fs.existsSync(dataFile)) {
    try { stores.push(JSON.parse(fs.readFileSync(dataFile, 'utf8'))); }
    catch (error) { throw new Error(`Cannot safely start PostgreSQL while ${path.basename(dataFile)} exists but is unreadable: ${error.message}`); }
  }
  if (fs.existsSync(databaseFile)) {
    let localDatabase;
    try {
      localDatabase = new (require('node:sqlite').DatabaseSync)(databaseFile, { readOnly: true });
      const hasStoreTable = localDatabase.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='agentguard_store'").get();
      if (hasStoreTable) {
        const row = localDatabase.prepare('SELECT payload FROM agentguard_store WHERE id=1').get();
        if (row) stores.push(JSON.parse(row.payload));
      }
    } catch (error) {
      throw new Error(`Cannot safely inspect ${path.basename(databaseFile)} before PostgreSQL startup: ${error.message}`);
    } finally { localDatabase?.close(); }
  }
  return stores;
}

function readStoreFromSqlite() {
  if (!database) return normalize(structuredClone(seed));
  const row = database.prepare('SELECT payload FROM agentguard_store WHERE id = 1').get();
  if (row) return normalize(JSON.parse(row.payload));
  if (fs.existsSync(dataFile)) {
    try { return normalize(JSON.parse(fs.readFileSync(dataFile, 'utf8'))); } catch { /* use seed */ }
  }
  return normalize(structuredClone(seed));
}

function readStore() {
  if (usePostgres) return cachedStore || normalize(structuredClone(seed));
  const store = readStoreFromSqlite();
  if (!database.prepare('SELECT 1 FROM agentguard_store WHERE id = 1').get()) writeStore(store);
  return store;
}

function writeStore(store) {
  const normalized = normalize(store);
  cachedStore = normalized;
  if (usePostgres) return;
  database.prepare(`
    INSERT INTO agentguard_store (id, schema_version, payload, updated_at)
    VALUES (1, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET schema_version=excluded.schema_version, payload=excluded.payload, updated_at=excluded.updated_at
  `).run(normalized.schemaVersion, JSON.stringify(normalized), new Date().toISOString());
}

async function loadPostgresRecords() {
  // The legacy compatibility table is no longer a runtime data source.
  // Relational PostgreSQL repositories are authoritative after cutover.
  return null;
}

async function loadRelationalStore() {
  const [workspaces, memberships, companies, agents, policies, approvals, assessments, incidents, events] = await Promise.all([
    pool.query('SELECT id,name,created_at,updated_at FROM ag_workspaces ORDER BY id'),
    pool.query('SELECT id,workspace_id,email,display_name,subject,role,created_at,updated_at FROM ag_memberships ORDER BY email'),
    pool.query('SELECT workspace_id,id,name,gateway_credential_hash,created_at,payload FROM ag_companies ORDER BY name,id'),
    pool.query('SELECT workspace_id,id,company_id,name,team,status,runtime_status,parent_id,credential_hash,last_seen_at,created_at,payload FROM ag_agents ORDER BY name,id'),
    pool.query('SELECT workspace_id,id,agent_id,name,effect,enabled,version,priority,created_at,updated_at,payload FROM ag_policies ORDER BY priority DESC,created_at DESC'),
    pool.query('SELECT workspace_id,id,agent_id,policy_id,status,action,action_ref,created_at,decided_at,payload FROM ag_approvals ORDER BY created_at DESC'),
    pool.query('SELECT workspace_id,id,agent_id,status,owner,review_due_at,created_at,updated_at,payload FROM ag_assessments ORDER BY updated_at DESC'),
    pool.query('SELECT workspace_id,id,agent_id,status,severity,title,owner,source_event_id,created_at,updated_at,resolved_at,payload FROM ag_incidents ORDER BY updated_at DESC'),
    pool.query('SELECT workspace_id,id,agent_id,kind,event_type,actor,message,created_at,previous_hash,event_hash,payload FROM ag_audit_events ORDER BY created_at DESC LIMIT 1000')
  ]);
  if (!workspaces.rowCount) return null;
  const iso = value => value?.toISOString?.() || value || null;
  return normalize({
    schemaVersion,
    workspaces: workspaces.rows.map(row => ({ id: row.id, name: row.name, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) })),
    memberships: memberships.rows.map(row => ({ id: row.id, workspaceId: row.workspace_id, email: row.email, name: row.display_name || row.email, subject: row.subject || null, role: row.role, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at), source: 'postgres' })),
    companies: companies.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, name: row.name, gatewayCredentialHash: row.gateway_credential_hash || row.payload?.gatewayCredentialHash, createdAt: iso(row.created_at) })),
    agents: agents.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, companyId: row.company_id, name: row.name, team: row.team, status: row.status, runtimeStatus: row.runtime_status, parentId: row.parent_id, credentialHash: row.credential_hash || row.payload?.credentialHash, lastSeenAt: iso(row.last_seen_at), createdAt: iso(row.created_at) })),
    policies: policies.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, name: row.name, effect: row.effect, enabled: row.enabled, version: row.version, priority: row.priority, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) })),
    approvals: approvals.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, policyId: row.policy_id || null, status: row.status, action: row.action, actionRef: row.action_ref || null, createdAt: iso(row.created_at), decidedAt: iso(row.decided_at) })),
    assessments: assessments.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id, status: row.status, owner: row.owner || null, reviewDueAt: iso(row.review_due_at), createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) })),
    incidents: incidents.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id || null, status: row.status, severity: row.severity, title: row.title, owner: row.owner || null, sourceEventId: row.source_event_id || null, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at), resolvedAt: iso(row.resolved_at) })),
    events: events.rows.map(row => ({ ...row.payload, workspaceId: row.workspace_id, id: row.id, agentId: row.agent_id || null, kind: row.kind, eventType: row.event_type || null, actor: row.actor, message: row.message, createdAt: iso(row.created_at), previousHash: row.previous_hash || null, eventHash: row.event_hash || null }))
  });
}

function assertPostgresBootstrapIsExplicit({ relationalStore, compatibilityStore, postgresStore, localStores = [] }) {
  if (relationalStore) return;
  if (compatibilityStore) throw new Error('PostgreSQL relational tables are empty but agentguard_records contains legacy data. Back up the database, then run `npm run migrate:relational` before starting AgentGuard. Startup will not implicitly bootstrap a partial relational view from the compatibility store.');
  if (hasApplicationData(postgresStore)) throw new Error('PostgreSQL relational tables are empty but the legacy agentguard_store contains application data. Startup will not partially import it; create a backup and migrate/reconcile it explicitly before starting AgentGuard.');
  if (localStores.some(hasApplicationData)) throw new Error('PostgreSQL relational tables are empty but local SQLite/JSON files contain application data. Startup will not ignore or partially import them; back up and migrate/reconcile that data explicitly before starting AgentGuard.');
}

async function initializeStore() {
  if (!usePostgres) { cachedStore = readStore(); return; }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS agentguard_metadata (
      id integer PRIMARY KEY CHECK (id = 1),
      schema_version integer NOT NULL,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);
  if (fs.existsSync(relationalSchemaFile)) await pool.query(fs.readFileSync(relationalSchemaFile, 'utf8'));
  await pool.query('ALTER TABLE ag_audit_events ADD COLUMN IF NOT EXISTS previous_hash text; ALTER TABLE ag_audit_events ADD COLUMN IF NOT EXISTS event_hash text;');
  cachedStore = await loadRelationalStore();
  if (cachedStore) return;

  // A legacy record-store snapshot cannot safely become the runtime cache:
  // the old bootstrap writer projected only some collections into relations.
  // Require the explicit, complete migration instead of silently starting with
  // incomplete relational data. Production writes no longer update this table.
  const compatibilityStore = await loadPostgresRecords();
  assertPostgresBootstrapIsExplicit({ relationalStore: cachedStore, compatibilityStore });

  const legacy = await pool.query(`SELECT to_regclass('public.agentguard_store') AS table_name`);
  let postgresStore = null;
  if (legacy.rows[0]?.table_name) {
    const result = await pool.query('SELECT payload FROM agentguard_store WHERE id = 1');
    if (result.rows[0]) postgresStore = normalize(result.rows[0].payload);
  }
  const localStores = readLocalStoreForMigrationCheck();
  assertPostgresBootstrapIsExplicit({ relationalStore: cachedStore, compatibilityStore, postgresStore, localStores });
  const fresh = normalize(structuredClone(seed));
  await postgresTransaction(async client => {
    await client.query('INSERT INTO ag_workspaces (id,name,created_at,updated_at) VALUES ($1,$2,now(),now()) ON CONFLICT (id) DO NOTHING', [fresh.workspaces[0].id, fresh.workspaces[0].name]);
    await client.query('INSERT INTO ag_companies (workspace_id,id,name,created_at,updated_at,payload) VALUES ($1,$2,$3,now(),now(),$4::jsonb) ON CONFLICT (workspace_id,id) DO NOTHING', ['default','default','Default workspace',JSON.stringify(fresh.companies[0])]);
    await client.query('INSERT INTO agentguard_metadata (id,schema_version,updated_at) VALUES (1,$1,now()) ON CONFLICT (id) DO UPDATE SET schema_version=EXCLUDED.schema_version,updated_at=now()', [schemaVersion]);
  });
  cachedStore = await loadRelationalStore();
}

async function flushStore() {}

async function postgresQuery(text, values) {
  if (!usePostgres) return null;
  return pool.query(text, values);
}

async function postgresTransaction(work) {
  if (!usePostgres) return undefined;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function closePostgres() { if (pool) await pool.end(); }

module.exports = { readStore, writeStore, initializeStore, flushStore, postgresQuery, postgresTransaction, closePostgres, databaseFile, usePostgres, hasApplicationData, assertPostgresBootstrapIsExplicit };
