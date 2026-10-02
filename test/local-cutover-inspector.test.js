const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { compareStores, summarizeAuditPair } = require('../scripts/inspect-local-cutover');

test('local snapshot comparison reports missing, divergent, and matching rows without returning payloads', () => {
  const report = compareStores(
    { agents: [{ id: 'a', workspaceId: 'w', name: 'SQLite value' }, { id: 'b', workspaceId: 'w' }] },
    { agents: [{ id: 'a', workspaceId: 'w', name: 'JSON value' }, { id: 'c', workspaceId: 'w' }] }
  );
  assert.deepEqual(report.find(item => item.collection === 'agents'), {
    collection: 'agents', sqliteCount: 2, jsonCount: 2, sqliteOnly: 1, jsonOnly: 1, payloadMismatches: 1
  });
  assert.equal(JSON.stringify(report).includes('SQLite value'), false);
  assert.equal(JSON.stringify(report).includes('JSON value'), false);
});

test('local cutover command wraps PostgreSQL inspection in a read-only transaction', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'inspect-local-cutover.js'), 'utf8');
  assert.match(source, /BEGIN READ ONLY/);
  assert.doesNotMatch(source, /\b(?:INSERT\s+INTO|UPDATE\s+\w+|DELETE\s+FROM|TRUNCATE)\b/i);
});

test('audit reconciliation summarizes stored hashes without exposing them', () => {
  const summary = summarizeAuditPair(
    [
      { id: 'same', workspaceId: 'w', eventHash: 'secret-a', message: 'private text' },
      { id: 'pg-only', workspaceId: 'w', eventHash: 'secret-b' }
    ],
    [
      { id: 'same', workspaceId: 'w', eventHash: 'secret-c', message: 'different private text' },
      { id: 'local-only', workspaceId: 'w' }
    ],
    ['postgres', 'sqlite']
  );
  assert.equal(summary.postgresOnly, 1);
  assert.equal(summary.sqliteOnly, 1);
  assert.equal(summary.shared, 1);
  assert.equal(summary.payloadMismatches, 1);
  assert.equal(summary.storedHashesDiffer, 1);
  assert.equal(summary.safeForAutomaticMerge, false);
  assert.equal(JSON.stringify(summary).includes('secret-'), false);
  assert.equal(JSON.stringify(summary).includes('private text'), false);
});
