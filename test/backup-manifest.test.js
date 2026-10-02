const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { gzipSync } = require('node:zlib');
const { createHash, generateKeyPairSync } = require('node:crypto');
const { createManifest, tableNames, verifyManifestSignature } = require('../scripts/postgres-backup-manifest');

function dump(rows = {}, names = tableNames) {
  return names.map(table => {
    const values = rows[table] || [];
    return `COPY public.${table} (id) FROM stdin;\n${values.length ? `${values.join('\n')}\n` : ''}\\.\n`;
  }).join('\n');
}

test('manifest counts rows in each required COPY section and binds to exact gzip bytes', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-manifest-'));
  try {
    const backup = path.join(directory, 'daily.sql.gz');
    fs.writeFileSync(backup, gzipSync(dump({ ag_agents: ['agent-1', 'agent-2'], ag_audit_events: ['event-1'] })));
    const first = await createManifest(backup);
    assert.equal(first.created, true);
    assert.equal(first.manifest.counts.ag_agents, 2);
    assert.equal(first.manifest.counts.ag_audit_events, 1);
    assert.equal(first.manifest.counts.ag_policies, 0);
    const same = await createManifest(backup);
    assert.equal(same.created, false);
    assert.equal(same.manifest.sha256, first.manifest.sha256);

    fs.writeFileSync(backup, gzipSync(dump({ ag_agents: ['different'] })));
    await assert.rejects(createManifest(backup), /Existing manifest does not match/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('pre-legal-hold manifests remain verifiable without rewriting historical backups', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-legacy-manifest-'));
  try {
    const backup = path.join(directory, 'legacy.sql.gz');
    const oldNames = tableNames.filter(name => name !== 'ag_audit_legal_holds');
    const bytes = gzipSync(dump({}, oldNames));
    fs.writeFileSync(backup, bytes);
    const previous = {
      format: 'agentguard-postgres-backup-manifest/v1', backup: path.basename(backup),
      sizeBytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
      counts: Object.fromEntries(oldNames.map(name => [name, 0])), generatedAt: new Date().toISOString()
    };
    fs.writeFileSync(`${backup}.manifest.json`, JSON.stringify(previous));
    const result = await createManifest(backup);
    assert.equal(result.created, false);
    assert.deepEqual(result.manifest.counts, previous.counts);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('manifest treats omitted table sections as zero observed rows', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-manifest-'));
  try {
    const backup = path.join(directory, 'partial.sql.gz');
    fs.writeFileSync(backup, gzipSync('COPY public.ag_workspaces (id) FROM stdin;\nws\n\\.\n'));
    const result = await createManifest(backup);
    assert.equal(result.manifest.counts.ag_workspaces, 1);
    assert.equal(result.manifest.counts.ag_agents, 0);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('manifest accepts declared empty tables whose COPY sections are omitted by pg_dump', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-empty-manifest-'));
  const backup = path.join(directory, 'empty-tables.sql.gz');
  const schema = tableNames.map(table => `CREATE TABLE public.${table} (id text);`).join('\n');
  fs.writeFileSync(backup, gzipSync(`${schema}\nCOPY public.ag_workspaces (id) FROM stdin;\nws\n\\.\n`));
  const result = await createManifest(backup);
  assert.equal(result.manifest.counts.ag_assessment_revisions, 0);
  assert.equal(result.manifest.counts.ag_workspaces, 1);
});

test('backup manifest can be signed and verified with an externally retained public key', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-signed-manifest-'));
  const previous = { privateFile: process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE, keyId: process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID };
  try {
    const backup = path.join(directory, 'signed.sql.gz'), privateFile = path.join(directory, 'private.pem'), publicFile = path.join(directory, 'public.pem');
    fs.writeFileSync(backup, gzipSync(dump()));
    const keys = generateKeyPairSync('ed25519');
    fs.writeFileSync(privateFile, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    fs.writeFileSync(publicFile, keys.publicKey.export({ type: 'spki', format: 'pem' }));
    process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE = privateFile;
    process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID = 'test-backup-key';
    const result = await createManifest(backup);
    assert.equal(result.document.signature.keyId, 'test-backup-key');
    assert.deepEqual(verifyManifestSignature(result.document, publicFile), { signed: true, keyId: 'test-backup-key' });
    const other = generateKeyPairSync('ed25519');
    const otherPublic = path.join(directory, 'other-public.pem');
    fs.writeFileSync(otherPublic, other.publicKey.export({ type: 'spki', format: 'pem' }));
    assert.throws(() => verifyManifestSignature(result.document, otherPublic), /invalid/);
  } finally {
    if (previous.privateFile === undefined) delete process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE; else process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE = previous.privateFile;
    if (previous.keyId === undefined) delete process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID; else process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID = previous.keyId;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('required signed manifests fail closed when signing configuration is missing', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-required-signature-'));
  const previous = {
    required: process.env.AGENTGUARD_REQUIRE_SIGNED_BACKUP_MANIFEST,
    privateFile: process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE,
    keyId: process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID
  };
  try {
    const backup = path.join(directory, 'unsigned.sql.gz');
    fs.writeFileSync(backup, gzipSync(dump()));
    process.env.AGENTGUARD_REQUIRE_SIGNED_BACKUP_MANIFEST = 'true';
    delete process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE;
    delete process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID;
    await assert.rejects(
      createManifest(backup),
      /Signed backup manifest is required but signing key configuration is missing/
    );
  } finally {
    if (previous.required === undefined) delete process.env.AGENTGUARD_REQUIRE_SIGNED_BACKUP_MANIFEST; else process.env.AGENTGUARD_REQUIRE_SIGNED_BACKUP_MANIFEST = previous.required;
    if (previous.privateFile === undefined) delete process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE; else process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE = previous.privateFile;
    if (previous.keyId === undefined) delete process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID; else process.env.AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID = previous.keyId;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
