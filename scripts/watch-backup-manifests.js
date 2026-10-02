const fs = require('node:fs');
const path = require('node:path');
const { createManifest, manifestPath } = require('./postgres-backup-manifest');

const backupRoot = process.env.BACKUP_ROOT || '/backups';
const stableForMs = Number(process.env.BACKUP_MANIFEST_STABLE_MS || 90_000);
const intervalMs = Number(process.env.BACKUP_MANIFEST_INTERVAL_MS || 60_000);
const loggedErrors = new Set();
let scanning = false;

function listFiles(directory, files = []) {
  if (!fs.existsSync(directory)) return files;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) listFiles(file, files);
    else if (entry.isFile() && entry.name.endsWith('.sql.gz')) files.push(file);
  }
  return files;
}

async function scan() {
  if (scanning) return;
  scanning = true;
  try {
    for (const backup of listFiles(backupRoot)) {
      try {
        const stat = fs.statSync(backup);
        if (!stat.size || Date.now() - stat.mtimeMs < stableForMs) continue;
        const sidecar = manifestPath(backup);
        if (fs.existsSync(sidecar)) {
          try {
            const current = JSON.parse(fs.readFileSync(sidecar, 'utf8'));
            if (current.sizeBytes === stat.size && current.backup === path.basename(backup)) continue;
          } catch { /* Leave malformed manifests for operator review. */ }
        }
        const result = await createManifest(backup);
        if (result.created) console.log(JSON.stringify({ event: 'backup_manifest_created', backup: path.relative(backupRoot, backup), bytes: stat.size }));
      } catch (error) {
        const key = `${backup}:${error.message}`;
        if (!loggedErrors.has(key)) console.error(JSON.stringify({ event: 'backup_manifest_failed', backup: path.relative(backupRoot, backup), error: error.message }));
        loggedErrors.add(key);
      }
    }
  } finally { scanning = false; }
}

scan().catch(error => console.error(error.message));
const timer = setInterval(() => scan().catch(error => console.error(error.message)), intervalMs);
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { clearInterval(timer); process.exit(0); });
