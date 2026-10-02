const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { inspect } = require('../scripts/inspect-postgres-cutover');

test('cutover inspector runs only read queries and checks membership payloads', async () => {
  const statements = [];
  const client = {
    async query(sql) {
      statements.push(sql);
      if (!/^\s*(SELECT|WITH)\b/i.test(sql)) throw new Error(`Non-read query attempted: ${sql}`);
      if (/information_schema\.tables/i.test(sql)) {
        return { rows: ['agentguard_records', 'ag_workspaces', 'ag_memberships', 'ag_companies', 'ag_agents', 'ag_policies', 'ag_approvals', 'ag_assessments', 'ag_incidents', 'ag_audit_events'].map(table_name => ({ table_name })) };
      }
      if (/FROM ag_memberships r/i.test(sql)) {
        assert.match(sql, /r\.role/);
        assert.match(sql, /l\.payload->>'role'/);
      }
      if (/WITH relational AS/i.test(sql)) return { rows: [{ legacyOnly: 0, relationalOnly: 0, payloadMismatches: 0, legacyOnlySamples: [], relationalOnlySamples: [], payloadMismatchSamples: [] }] };
      if (/AS "relationalCount"/i.test(sql)) return { rows: [{ relationalCount: 0, legacyCount: 0 }] };
      throw new Error(`Unexpected inspector query: ${sql}`);
    }
  };
  const report = await inspect(client);
  assert.equal(report.readOnly, true);
  assert.equal(report.legacyTablePresent, true);
  assert.equal(report.relationalSchemaReady, true);
  assert.equal(report.mirrorInSync, true);
  assert.ok(statements.length > 1);

  const source = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'inspect-postgres-cutover.js'), 'utf8');
  assert.match(source, /BEGIN READ ONLY/);
  assert.doesNotMatch(source, /\b(?:INSERT\s+INTO|UPDATE\s+\w+|DELETE\s+FROM|TRUNCATE)\b/i);
});
