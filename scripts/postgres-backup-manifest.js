const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomBytes, createPrivateKey, createPublicKey, sign, verify } = require('node:crypto');
const { createReadStream } = require('node:fs');
const { createGunzip } = require('node:zlib');
const readline = require('node:readline');
const { Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');

const tableNames = ['ag_workspaces', 'ag_memberships', 'ag_companies', 'ag_agents', 'ag_policies', 'ag_approvals', 'ag_governed_actions', 'ag_assessments', 'ag_assessment_revisions', 'ag_incidents', 'ag_alerts', 'ag_alert_deliveries', 'ag_audit_events', 'ag_audit_legal_holds', 'ag_telemetry_receipts'];
const previousTableNames = tableNames.filter(name => name !== 'ag_assessment_revisions');
const legacyTableNames = previousTableNames.filter(name => name !== 'ag_audit_legal_holds');
const noHoldCurrentTableNames = tableNames.filter(name => name !== 'ag_audit_legal_holds');

async function sha256File(file) {
  const hash = createHash('sha256');
  await pipeline(createReadStream(file), new Transform({ transform(chunk, encoding, callback) { hash.update(chunk); callback(null, chunk); } }), new Transform({ transform(chunk, encoding, callback) { callback(); } }));
  return hash.digest('hex');
}

async function countDumpRows(file, requiredNames = tableNames) {
  const counts = Object.fromEntries(requiredNames.map(name => [name, 0]));
  const targets = new Set(requiredNames);
  const lines = readline.createInterface({ input: createReadStream(file).pipe(createGunzip()), crlfDelay: Infinity });
  let current = null, found = new Set(), declared = new Set();
  for await (const line of lines) {
    if (current) {
      if (line === '\\.') current = null;
      else if (current.target) counts[current.target]++;
      continue;
    }
    const create = /^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?:"?public"?)\.)?"?([A-Za-z0-9_]+)"?\s*\(/i.exec(line);
    if (create && targets.has(create[1])) declared.add(create[1]);
    const match = /^COPY\s+(?:public\.)?"?([A-Za-z0-9_]+)"?\s+\(.+\)\s+FROM\s+stdin;$/.exec(line);
    if (!match) continue;
    const table = match[1];
    current = { target: targets.has(table) ? table : null };
    if (current.target) found.add(current.target);
  }
  if (current) throw new Error('Compressed SQL dump ended inside a COPY data section');
  // pg_dump may omit both schema and COPY data sections for tables excluded by
  // a filtered dump. Missing sections therefore represent zero observed rows;
  // malformed/truncated COPY sections are still rejected above.
  return counts;
}

function manifestPath(backupPath) { return `${backupPath}.manifest.json`; }

async function createManifest(backupPath) {
  const stat = fs.statSync(backupPath);
  if (!stat.isFile() || stat.size === 0 || !backupPath.endsWith('.sql.gz')) throw new Error('Manifest input must be a non-empty .sql.gz file');
  const digest = await sha256File(backupPath);
  const target = manifestPath(backupPath);
  const existing = fs.existsSync(target) ? JSON.parse(fs.readFileSync(target, 'utf8')) : null;
  const existingNames = existing ? Object.keys(existing.counts || {}) : null;
  const knownLegacyShape = JSON.stringify(existingNames) === JSON.stringify(legacyTableNames);
  const knownPreviousShape = JSON.stringify(existingNames) === JSON.stringify(previousTableNames);
  const knownNoHoldCurrentShape = JSON.stringify(existingNames) === JSON.stringify(noHoldCurrentTableNames);
  const knownCurrentShape = JSON.stringify(existingNames) === JSON.stringify(tableNames);
  if (existing && !knownLegacyShape && !knownPreviousShape && !knownNoHoldCurrentShape && !knownCurrentShape) throw new Error('Existing manifest has an unsupported table list');
  const counts = await countDumpRows(backupPath, knownLegacyShape ? legacyTableNames : knownPreviousShape ? previousTableNames : knownNoHoldCurrentShape ? noHoldCurrentTableNames : tableNames);
  const manifest = { format: 'agentguard-postgres-backup-manifest/v1', backup: path.basename(backupPath), sizeBytes: stat.size, sha256: digest, counts, generatedAt: new Date().toISOString() };
  const signingKeyFile = process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE || process.env.AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_FILE;
  const signingKeyId = process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID || process.env.AGENTGUARD_AUDIT_SIGNING_KEY_ID;
  const signature = signingKeyFile && signingKeyId && fs.existsSync(path.resolve(signingKeyFile))
    ? { algorithm: 'Ed25519', keyId: signingKeyId, value: sign(null, Buffer.from(JSON.stringify(manifest)), createPrivateKey(fs.readFileSync(path.resolve(signingKeyFile)))).toString('base64url') }
    : null;
  const document = signature ? { manifest, signature } : manifest;
  if (fs.existsSync(target)) {
    if (existing.manifest ? existing.manifest.format !== 'agentguard-postgres-backup-manifest/v1' : existing.format !== 'agentguard-postgres-backup-manifest/v1') throw new Error(`Existing manifest has an unsupported format for ${path.basename(backupPath)}`);
    const candidate = existing.manifest || existing;
    if (candidate.backup !== path.basename(backupPath) || candidate.sizeBytes !== stat.size || candidate.sha256 !== digest || JSON.stringify(candidate.counts) !== JSON.stringify(counts)) throw new Error(`Existing manifest does not match ${path.basename(backupPath)}; preserve it and investigate before regeneration`);
    return { manifest: candidate, document: existing, path: target, created: false };
  }
  const temporary = `${target}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(document, null, 2)}\n`, { flag: 'wx' });
  try { fs.renameSync(temporary, target); }
  catch (error) {
    try { fs.unlinkSync(temporary); } catch { /* no orphaned temp report */ }
    if (fs.existsSync(target)) {
      const concurrent = JSON.parse(fs.readFileSync(target, 'utf8'));
      const candidate = concurrent.manifest || concurrent;
      if (candidate.sha256 === digest && JSON.stringify(candidate.counts) === JSON.stringify(counts)) return { manifest: candidate, document: concurrent, path: target, created: false };
    }
    throw error;
  }
  return { manifest, document, path: target, created: true };
}

function verifyManifestSignature(document, publicKeyFile) {
  if (!document?.signature) return { signed: false };
  if (!publicKeyFile || !fs.existsSync(path.resolve(publicKeyFile))) throw new Error('Signed backup manifest requires AGENTGUARD_BACKUP_MANIFEST_PUBLIC_KEY_FILE');
  const manifest = document.manifest;
  if (document.signature.algorithm !== 'Ed25519' || !document.signature.keyId || !document.signature.value) throw new Error('Backup manifest signature metadata is invalid');
  const valid = verify(null, Buffer.from(JSON.stringify(manifest)), createPublicKey(fs.readFileSync(path.resolve(publicKeyFile))), Buffer.from(document.signature.value, 'base64url'));
  if (!valid) throw new Error('Backup manifest signature is invalid');
  return { signed: true, keyId: document.signature.keyId };
}

module.exports = { tableNames, manifestPath, createManifest, countDumpRows, verifyManifestSignature };

if (require.main === module) {
  const candidate = process.argv.find((arg, index) => process.argv[index - 1] === '--backup');
  if (!candidate) { console.error('Usage: node scripts/postgres-backup-manifest.js --backup backups/daily/agentguard-YYYYMMDD.sql.gz'); process.exit(2); }
  const root = path.resolve(__dirname, '..');
  const backup = path.resolve(root, candidate), relative = path.relative(path.join(root, 'backups'), backup);
  if (relative.startsWith('..') || path.isAbsolute(relative)) { console.error('--backup must identify a file under backups/'); process.exit(2); }
  createManifest(backup).then(result => console.log(JSON.stringify({ ok: true, manifest: path.relative(root, result.path), created: result.created, sha256: result.manifest.sha256, counts: result.manifest.counts }))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
