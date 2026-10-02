const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(process.env.BACKUP_ROOT || path.join(__dirname, '..', 'backups'));
const maxAgeHours = Number(process.env.AGENTGUARD_BACKUP_MAX_AGE_HOURS || 26);
const now = Date.now();

function walk(directory, result = []) {
  if (!fs.existsSync(directory)) return result;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(file, result);
    else if (/\.sql\.gz$|\.json$/.test(entry.name) && !entry.name.includes('-latest.')) result.push(file);
  }
  return result;
}

const files = walk(root).map(file => ({ file, modifiedAt: fs.statSync(file).mtimeMs }))
  .sort((a, b) => b.modifiedAt - a.modifiedAt);
const latest = files[0] || null;
const ageHours = latest ? (now - latest.modifiedAt) / 3_600_000 : null;
const result = {
  ok: Boolean(latest && ageHours <= maxAgeHours),
  status: latest ? (ageHours <= maxAgeHours ? 'healthy' : 'overdue') : 'missing',
  root,
  maxAgeHours,
  latestBackup: latest ? { path: path.relative(process.cwd(), latest.file), modifiedAt: new Date(latest.modifiedAt).toISOString(), ageHours: Number(ageHours.toFixed(2)) } : null,
  checkedAt: new Date(now).toISOString()
};
console.log(JSON.stringify(result));
if (!result.ok) process.exitCode = 1;
