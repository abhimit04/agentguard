const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const { auditHash, stableStringify } = require('../audit-integrity');
const { verifyExport } = require('../scripts/verify-audit-export');
const { archiveExport, verifyArchive, verifyContinuation } = require('../scripts/audit-archive');

function makePair() {
  return generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
}

async function writeSignedExport(directory, keyId, privateKey, { sequence = 1, previousHash = null } = {}) {
  const event = { id: `event-${keyId}-${sequence}`, workspaceId: 'rotation-test', message: `Signed by ${keyId}` };
  const eventHash = auditHash(previousHash, event, 'rotation-test');
  const eventBytes = Buffer.from(`${stableStringify({ recordType: 'event', workspaceId: 'rotation-test', chainSequence: sequence, previousHash, eventHash, event })}\n`);
  const manifest = {
    format: 'agentguard-audit-ndjson-v1', workspaceId: 'rotation-test', eventCount: 1,
    firstSequence: sequence, lastSequence: sequence, predecessorHash: previousHash, headHash: eventHash,
    fileSha256: createHash('sha256').update(eventBytes).digest('hex'), signingKeyId: keyId,
    signatureAlgorithm: 'Ed25519'
  };
  const signature = sign(null, Buffer.from(stableStringify(manifest)), privateKey).toString('base64url');
  const filePath = path.join(directory, `${keyId}-${sequence}.ndjson`);
  const manifestLine = Buffer.from(`${stableStringify({ recordType: 'manifest', manifest, signature: { algorithm: 'Ed25519', keyId, value: signature } })}\n`);
  await fs.writeFile(filePath, Buffer.concat([manifestLine, eventBytes]));
  return filePath;
}

test('trusted keyring verifies exports across signing-key rotation and rejects unknown keys', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'agentguard-key-rotation-test-'));
  try {
    const oldPair = makePair();
    const activePair = makePair();
    await fs.writeFile(path.join(directory, 'old-public.pem'), oldPair.publicKey);
    await fs.writeFile(path.join(directory, 'active-public.pem'), activePair.publicKey);
    const oldExport = await writeSignedExport(directory, 'audit-2026-q3', oldPair.privateKey);
    const activeExport = await writeSignedExport(directory, 'audit-2026-q4', activePair.privateKey);
    const keyringPath = path.join(directory, 'trusted-keys.json');
    await fs.writeFile(keyringPath, JSON.stringify({
      format: 'agentguard-audit-keyring-v1',
      keys: { 'audit-2026-q3': 'old-public.pem', 'audit-2026-q4': 'active-public.pem' }
    }));

    assert.equal((await verifyExport(oldExport, keyringPath)).signingKeyId, 'audit-2026-q3');
    assert.equal((await verifyExport(activeExport, keyringPath)).signingKeyId, 'audit-2026-q4');

    const unknownExport = await writeSignedExport(directory, 'untrusted-key', makePair().privateKey);
    await assert.rejects(verifyExport(unknownExport, keyringPath), /is not trusted by this keyring/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('signed archive checkpoint verifies its export and a linked continuation', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'agentguard-checkpoint-test-'));
  try {
    const pair = makePair();
    const publicPath = path.join(directory, 'trusted.pem');
    const privatePath = path.join(directory, 'signing.pem');
    await fs.writeFile(publicPath, pair.publicKey);
    await fs.writeFile(privatePath, pair.privateKey);
    const firstExport = await writeSignedExport(directory, 'checkpoint-test', pair.privateKey);
    const first = await verifyExport(firstExport, publicPath);
    const archiveDirectory = path.join(directory, 'archive');
    const archived = await archiveExport(firstExport, publicPath, archiveDirectory, privatePath, 'checkpoint-test');
    assert.equal((await verifyArchive(archived.checkpointPath, publicPath)).checkpoint.headHash, first.headHash);
    const nextExport = await writeSignedExport(directory, 'checkpoint-test', pair.privateKey, { sequence: 2, previousHash: first.headHash });
    assert.equal((await verifyContinuation(archived.checkpointPath, nextExport, publicPath)).continuedThrough, 2);
    const unrelatedExport = await writeSignedExport(directory, 'other-key', pair.privateKey, { sequence: 3 });
    await assert.rejects(verifyContinuation(archived.checkpointPath, unrelatedExport, publicPath), /does not link to the checkpoint head/);
    const checkpointDocument = JSON.parse(await fs.readFile(archived.checkpointPath, 'utf8'));
    checkpointDocument.checkpoint.headHash = '0'.repeat(64);
    await fs.writeFile(archived.checkpointPath, JSON.stringify(checkpointDocument));
    await assert.rejects(verifyArchive(archived.checkpointPath, publicPath), /Checkpoint signature is invalid/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('single public PEM remains supported for offline verification', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'agentguard-single-key-test-'));
  try {
    const pair = makePair();
    const publicPath = path.join(directory, 'public.pem');
    await fs.writeFile(publicPath, pair.publicKey);
    const exportPath = await writeSignedExport(directory, 'single-key', pair.privateKey);
    assert.equal((await verifyExport(exportPath, publicPath)).ok, true);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
