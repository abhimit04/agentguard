const test = require('node:test');
const assert = require('node:assert/strict');
const { assertPostgresBootstrapIsExplicit, hasApplicationData } = require('../storage');

test('relational workspace data takes precedence without consulting legacy fallback', () => {
  assert.doesNotThrow(() => assertPostgresBootstrapIsExplicit({ relationalStore: { workspaces: [{ id: 'default' }] }, compatibilityStore: { agents: [{ id: 'old' }] }, localStores: [{ agents: [{ id: 'local' }] }] }));
});

test('legacy PostgreSQL records cannot implicitly bootstrap a partial relational store', () => {
  assert.throws(
    () => assertPostgresBootstrapIsExplicit({ relationalStore: null, compatibilityStore: { agents: [{ id: 'old' }] } }),
    /Back up the database, then run `npm run migrate:relational`/
  );
});

test('legacy PostgreSQL blob data is not partially imported at startup', () => {
  assert.throws(
    () => assertPostgresBootstrapIsExplicit({ relationalStore: null, compatibilityStore: null, postgresStore: { agents: [{ id: 'old' }], policies: [] } }),
    /legacy agentguard_store contains application data/
  );
});

test('SQLite and JSON fallback data is not silently ignored by a fresh PostgreSQL store', () => {
  assert.throws(
    () => assertPostgresBootstrapIsExplicit({ relationalStore: null, compatibilityStore: null, localStores: [{ agents: [{ id: 'local' }] }] }),
    /local SQLite\/JSON files contain application data/
  );
});

test('empty compatibility sources allow the normal fresh-database bootstrap path', () => {
  assert.doesNotThrow(() => assertPostgresBootstrapIsExplicit({ relationalStore: null, compatibilityStore: null, postgresStore: null, localStores: [{ workspaces: [{ id: 'default', name: 'AgentGuard Workspace' }], companies: [{ id: 'default', workspaceId: 'default', name: 'Default workspace' }], agents: [], policies: [], approvals: [], assessments: [], incidents: [], events: [] }] }));
  assert.equal(hasApplicationData({ agents: [], policies: [], approvals: [], events: [] }), false);
  assert.equal(hasApplicationData({ companies: [{ id: 'default', workspaceId: 'default', name: 'Default workspace', gatewayCredentialHash: 'stored-hash' }] }), true);
});
