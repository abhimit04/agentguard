const fs = require('node:fs/promises');
const { createPublicKey, verify: verifySignature, createHash } = require('node:crypto');
const { stableStringify, verifyAuditPage } = require('../audit-integrity');

async function loadTrustedPublicKey(publicKeyPathOrKeyring, keyId) {
  const configuredBytes = await fs.readFile(publicKeyPathOrKeyring);
  let keyPath = publicKeyPathOrKeyring;
  try {
    const keyring = JSON.parse(configuredBytes.toString('utf8'));
    if (!keyring || keyring.format !== 'agentguard-audit-keyring-v1' || !keyring.keys || typeof keyring.keys !== 'object') throw new Error('Unsupported trusted keyring format');
    const configuredPath = keyring.keys[keyId];
    if (typeof configuredPath !== 'string' || !configuredPath.trim()) throw new Error(`Signing key ${keyId} is not trusted by this keyring`);
    keyPath = require('node:path').resolve(require('node:path').dirname(publicKeyPathOrKeyring), configuredPath);
  } catch (error) {
    if (error instanceof SyntaxError) {
      // A PEM file is still accepted for single-key verification.
    } else {
      throw error;
    }
  }
  const publicKey = createPublicKey(await fs.readFile(keyPath));
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Verification key must be Ed25519');
  return publicKey;
}

async function verifyExport(filePath, publicKeyPathOrKeyring) {
  const bytes = await fs.readFile(filePath);
  const firstNewline = bytes.indexOf(0x0a);
  if (firstNewline < 0) throw new Error('Export is missing its NDJSON manifest line');
  const manifestLine = JSON.parse(bytes.subarray(0, firstNewline).toString('utf8'));
  if (manifestLine.recordType !== 'manifest' || manifestLine.manifest?.format !== 'agentguard-audit-ndjson-v1') throw new Error('Unsupported export manifest');
  const { manifest, signature } = manifestLine;
  if (signature?.algorithm !== 'Ed25519' || signature.keyId !== manifest.signingKeyId || manifest.signatureAlgorithm !== 'Ed25519') throw new Error('Manifest signing metadata is inconsistent');
  const publicKey = await loadTrustedPublicKey(publicKeyPathOrKeyring, manifest.signingKeyId);
  if (!verifySignature(null, Buffer.from(stableStringify(manifest)), publicKey, Buffer.from(signature.value || '', 'base64url'))) throw new Error('Manifest signature is invalid');

  const eventBytes = bytes.subarray(firstNewline + 1);
  const actualDigest = createHash('sha256').update(eventBytes).digest('hex');
  if (actualDigest !== manifest.fileSha256) throw new Error('NDJSON event bytes do not match the manifest digest');
  const lines = eventBytes.toString('utf8').split('\n').filter(Boolean);
  const rows = lines.map((line, index) => {
    const item = JSON.parse(line);
    if (item.recordType !== 'event' || item.workspaceId !== manifest.workspaceId) throw new Error(`Invalid event record at line ${index + 2}`);
    return { workspace_id: item.workspaceId, id: item.event?.id, chain_sequence: item.chainSequence, previous_hash: item.previousHash, event_hash: item.eventHash, payload: item.event };
  });
  const state = { workspaceId: manifest.workspaceId, previousHash: manifest.predecessorHash || null, headHash: null, checked: 0, startSequence: null, endSequence: null };
  const result = verifyAuditPage(state, rows);
  if (result.failure) throw new Error(`Hash chain invalid at sequence ${result.failure.sequence}: ${result.failure.reason}`);
  if (rows.length !== manifest.eventCount) throw new Error(`Event count mismatch: found ${rows.length}, expected ${manifest.eventCount}`);
  if ((rows[0]?.chain_sequence ?? null) !== manifest.firstSequence || (rows.at(-1)?.chain_sequence ?? null) !== manifest.lastSequence) throw new Error('Sequence range does not match the manifest');
  if ((rows.at(-1)?.event_hash || null) !== manifest.headHash) throw new Error('Head hash does not match the manifest');
  return { ok: true, workspaceId: manifest.workspaceId, eventCount: rows.length, firstSequence: manifest.firstSequence, lastSequence: manifest.lastSequence, predecessorHash: manifest.predecessorHash || null, headHash: manifest.headHash, signingKeyId: manifest.signingKeyId, fileSha256: actualDigest };
}

if (require.main === module) {
  const [filePath, publicKeyPath] = process.argv.slice(2);
  if (!filePath || !publicKeyPath) {
    console.error('Usage: node scripts/verify-audit-export.js <export.ndjson> <public-key.pem|trusted-keyring.json>');
    process.exitCode = 2;
  } else verifyExport(filePath, publicKeyPath).then(result => console.log(JSON.stringify(result))).catch(error => { console.error(error.message); process.exitCode = 1; });
}

module.exports = { verifyExport, loadTrustedPublicKey };
