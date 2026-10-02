const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
function sourceFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(filename);
    return entry.isFile() && entry.name.endsWith('.js') ? [filename] : [];
  });
}

test('runtime audit event DML is centralized in the governance repository', () => {
  const runtimeFiles = [path.join(root, 'server.js'), path.join(root, 'storage.js'), ...sourceFiles(path.join(root, 'repositories'))];
  const writes = [];
  const mutation = /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+(?:public\.)?ag_audit_events\b/ig;
  for (const filename of runtimeFiles) {
    const content = fs.readFileSync(filename, 'utf8');
    if (mutation.test(content)) writes.push(path.relative(root, filename).replaceAll('\\', '/'));
    mutation.lastIndex = 0;
  }
  assert.deepEqual(writes, ['repositories/governance.js']);
});

test('runtime never creates or mutates the compatibility-record store', () => {
  const runtimeFiles = [path.join(root, 'server.js'), path.join(root, 'storage.js'), ...sourceFiles(path.join(root, 'repositories'))];
  const mutation = /\b(?:(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+(?:public\.)?agentguard_records|CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+(?:public\.)?agentguard_records)\b/ig;
  const writes = [];
  for (const filename of runtimeFiles) {
    const content = fs.readFileSync(filename, 'utf8');
    if (mutation.test(content)) writes.push(path.relative(root, filename).replaceAll('\\', '/'));
    mutation.lastIndex = 0;
  }
  assert.deepEqual(writes, [], 'normal runtime code must never create or mutate the compatibility mirror');
});
