const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const script = path.resolve(__dirname, '..', 'scripts', 'check-backup-freshness.js');

function run(root, maxAgeHours = '26') {
  const env = { ...process.env, BACKUP_ROOT: root, AGENTGUARD_BACKUP_MAX_AGE_HOURS: maxAgeHours };
  try {
    return { status: 0, value: JSON.parse(execFileSync(process.execPath, [script], { env, encoding: 'utf8' })) };
  } catch (error) {
    return { status: error.status, value: JSON.parse(error.stdout) };
  }
}

test('backup freshness reports healthy, overdue, and missing states', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-backup-freshness-'));
  try {
    assert.equal(run(root).value.status, 'missing');
    fs.writeFileSync(path.join(root, 'backup.sql.gz'), 'backup');
    assert.equal(run(root).value.status, 'healthy');
    fs.utimesSync(path.join(root, 'backup.sql.gz'), new Date(0), new Date(0));
    const overdue = run(root, '1');
    assert.equal(overdue.status, 1);
    assert.equal(overdue.value.status, 'overdue');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
