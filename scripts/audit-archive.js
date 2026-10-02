const fs = require('node:fs/promises');
const path = require('node:path');
const { constants } = require('node:fs');
const { createPrivateKey, sign, verify: verifySignature } = require('node:crypto');
const { stableStringify } = require('../audit-integrity');
const { verifyExport, loadTrustedPublicKey } = require('./verify-audit-export');

const FORMAT = 'agentguard-audit-checkpoint-v1';

function assertArchiveName(name) {
  if (typeof name !== 'string' || !/^[A-Za-z0-9._-]+\.ndjson$/.test(name) || name === '.' || name === '..') throw new Error('Checkpoint archive name is invalid');
}

async function readCheckpoint(checkpointPath, trustedKeysPath) {
  const document = JSON.parse(await fs.readFile(checkpointPath, 'utf8'));
  const { checkpoint, signature } = document;
  if (document.recordType !== 'audit-checkpoint' || checkpoint?.format !== FORMAT) throw new Error('Unsupported audit checkpoint');
  assertArchiveName(checkpoint.archiveFile);
  if (signature?.algorithm !== 'Ed25519' || signature.keyId !== checkpoint.signingKeyId || checkpoint.signatureAlgorithm !== 'Ed25519') throw new Error('Checkpoint signing metadata is inconsistent');
  const publicKey = await loadTrustedPublicKey(trustedKeysPath, checkpoint.signingKeyId);
  if (!verifySignature(null, Buffer.from(stableStringify(checkpoint)), publicKey, Buffer.from(signature.value || '', 'base64url'))) throw new Error('Checkpoint signature is invalid');
  return checkpoint;
}

async function verifyArchive(checkpointPath, trustedKeysPath) {
  const checkpoint = await readCheckpoint(checkpointPath, trustedKeysPath);
  const archivePath = path.join(path.dirname(checkpointPath), checkpoint.archiveFile);
  const exportResult = await verifyExport(archivePath, trustedKeysPath);
  for (const [field, value] of Object.entries({
    workspaceId: exportResult.workspaceId,
    firstSequence: exportResult.firstSequence,
    lastSequence: exportResult.lastSequence,
    eventCount: exportResult.eventCount,
    predecessorHash: exportResult.predecessorHash,
    headHash: exportResult.headHash,
    fileSha256: exportResult.fileSha256
  })) if (checkpoint[field] !== value) throw new Error(`Checkpoint ${field} does not match the archived export`);
  if (!Number.isSafeInteger(checkpoint.eventCount) || checkpoint.eventCount < 1) throw new Error('Empty audit segments cannot form a checkpoint');
  return { ok: true, checkpoint, archivePath };
}

async function archiveExport(exportPath, trustedKeysPath, archiveDirectory, privateKeyPath, signingKeyId) {
  if (typeof signingKeyId !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(signingKeyId)) throw new Error('A valid checkpoint signing key ID is required');
  const verified = await verifyExport(exportPath, trustedKeysPath);
  if (!verified.eventCount) throw new Error('Empty audit segments cannot be archived as checkpoints');
  const privateKey = createPrivateKey(await fs.readFile(privateKeyPath));
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Checkpoint signing key must be Ed25519');
  const trustedSigningKey = await loadTrustedPublicKey(trustedKeysPath, signingKeyId);
  const proof = Buffer.from('agentguard-audit-checkpoint-key-match-v1');
  if (!verifySignature(null, proof, trustedSigningKey, sign(null, proof, privateKey))) throw new Error('Checkpoint private key does not match the trusted key ID');
  await fs.mkdir(archiveDirectory, { recursive: true });
  const archiveFile = `agentguard-audit-${verified.workspaceId.replace(/[^A-Za-z0-9._-]/g, '_')}-${verified.firstSequence}-${verified.lastSequence}-${verified.fileSha256.slice(0, 16)}.ndjson`;
  assertArchiveName(archiveFile);
  const archivePath = path.join(archiveDirectory, archiveFile);
  const checkpointPath = `${archivePath}.checkpoint.json`;
  const checkpoint = {
    format: FORMAT,
    workspaceId: verified.workspaceId,
    firstSequence: verified.firstSequence,
    lastSequence: verified.lastSequence,
    eventCount: verified.eventCount,
    predecessorHash: verified.predecessorHash,
    headHash: verified.headHash,
    fileSha256: verified.fileSha256,
    archiveFile,
    createdAt: new Date().toISOString(),
    signingKeyId,
    signatureAlgorithm: 'Ed25519'
  };
  const signature = sign(null, Buffer.from(stableStringify(checkpoint)), privateKey).toString('base64url');
  await fs.copyFile(exportPath, archivePath, constants.COPYFILE_EXCL);
  await fs.writeFile(checkpointPath, `${stableStringify({ recordType: 'audit-checkpoint', checkpoint, signature: { algorithm: 'Ed25519', keyId: signingKeyId, value: signature } })}\n`, { flag: 'wx' });
  await verifyArchive(checkpointPath, trustedKeysPath);
  return { checkpointPath, archivePath, workspaceId: verified.workspaceId, headHash: verified.headHash, lastSequence: verified.lastSequence };
}

async function verifyContinuation(checkpointPath, nextExportPath, trustedKeysPath) {
  const { checkpoint } = await verifyArchive(checkpointPath, trustedKeysPath);
  const next = await verifyExport(nextExportPath, trustedKeysPath);
  if (next.workspaceId !== checkpoint.workspaceId) throw new Error('Continuation workspace does not match the checkpoint');
  if (next.firstSequence === null || next.firstSequence <= checkpoint.lastSequence) throw new Error('Continuation sequence must follow the checkpoint');
  if (next.predecessorHash !== checkpoint.headHash) throw new Error('Continuation does not link to the checkpoint head');
  return { ok: true, workspaceId: checkpoint.workspaceId, archivedThrough: checkpoint.lastSequence, continuedThrough: next.lastSequence, headHash: next.headHash };
}

module.exports = { archiveExport, verifyArchive, verifyContinuation, readCheckpoint };
