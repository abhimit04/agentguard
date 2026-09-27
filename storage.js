const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { Pool } = require('pg');

const dataFile = path.join(__dirname, 'data.json');
const databaseFile = path.join(__dirname, 'agentguard.sqlite');
const seed = { schemaVersion: 8, companies: [{ id: 'default', name: 'Default workspace' }], agents: [], policies: [], approvals: [], assessments: [], events: [] };
const usePostgres = process.env.AGENTGUARD_STORAGE === 'postgres' || Boolean(process.env.DATABASE_URL);
const pool = usePostgres ? new Pool({ connectionString: process.env.DATABASE_URL || `postgresql://${encodeURIComponent(process.env.POSTGRES_USER || 'agentguard')}:${encodeURIComponent(process.env.POSTGRES_PASSWORD || '')}@127.0.0.1:${process.env.POSTGRES_PORT || 5432}/${process.env.POSTGRES_DB || 'agentguard'}` }) : null;
let cachedStore = null;

const database = new DatabaseSync(databaseFile);
database.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS agentguard_store (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);

function normalize(store) {
  store.schemaVersion = 8;
  store.companies = Array.isArray(store.companies) && store.companies.length ? store.companies : [{ id: 'default', name: 'Default workspace' }];
  store.agents = Array.isArray(store.agents) ? store.agents : [];
  for (const agent of store.agents) agent.companyId = agent.companyId || 'default';
  store.policies = Array.isArray(store.policies) ? store.policies : [];
  store.approvals = Array.isArray(store.approvals) ? store.approvals : [];
  store.assessments = Array.isArray(store.assessments) ? store.assessments : [];
  store.events = Array.isArray(store.events) ? store.events : [];
  return store;
}

function readStore() {
  if (usePostgres) return cachedStore || seed;
  const row = database.prepare('SELECT payload FROM agentguard_store WHERE id = 1').get();
  if (row) return normalize(JSON.parse(row.payload));
  let store = seed;
  if (fs.existsSync(dataFile)) {
    try { store = normalize(JSON.parse(fs.readFileSync(dataFile, 'utf8'))); } catch { store = seed; }
  }
  writeStore(store);
  return store;
}

function writeStore(store) {
  const normalized = normalize(store);
  cachedStore = normalized;
  if (usePostgres) {
    pool.query(`INSERT INTO agentguard_store (id, schema_version, payload, updated_at) VALUES (1, $1, $2, now()) ON CONFLICT (id) DO UPDATE SET schema_version=EXCLUDED.schema_version, payload=EXCLUDED.payload, updated_at=now()`, [normalized.schemaVersion, JSON.stringify(normalized)]).catch(error => console.error('PostgreSQL write failed:', error.message));
    return;
  }
  database.prepare(`
    INSERT INTO agentguard_store (id, schema_version, payload, updated_at)
    VALUES (1, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET schema_version=excluded.schema_version, payload=excluded.payload, updated_at=excluded.updated_at
  `).run(normalized.schemaVersion, JSON.stringify(normalized), new Date().toISOString());
}

async function initializeStore() {
  if (!usePostgres) { cachedStore = readStore(); return; }
  await pool.query('CREATE TABLE IF NOT EXISTS agentguard_store (id integer PRIMARY KEY, schema_version integer NOT NULL, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())');
  const result = await pool.query('SELECT payload FROM agentguard_store WHERE id = 1');
  if (result.rows[0]) cachedStore = normalize(result.rows[0].payload);
  else {
    const sqliteStore = (() => { try { return readStoreFromSqlite(); } catch { return seed; } })();
    cachedStore = normalize(sqliteStore);
    await pool.query('INSERT INTO agentguard_store (id, schema_version, payload) VALUES (1, $1, $2)', [cachedStore.schemaVersion, JSON.stringify(cachedStore)]);
  }
}
function readStoreFromSqlite() {
  const row = database.prepare('SELECT payload FROM agentguard_store WHERE id = 1').get();
  return row ? JSON.parse(row.payload) : seed;
}

module.exports = { readStore, writeStore, initializeStore, databaseFile };
