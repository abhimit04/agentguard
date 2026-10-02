const fs = require('node:fs/promises');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');

async function generateKeys() {
  const directory = path.resolve(__dirname, '..', 'secrets');
  await fs.mkdir(directory, { recursive: true });
  const keyId = process.argv[2];
  if (keyId && !/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) throw new Error('Key ID must be 1–64 letters, numbers, dots, underscores, or hyphens');
  const stem = keyId ? `audit-signing-${keyId}` : 'audit-signing';
  const privatePath = path.join(directory, `${stem}-private.pem`);
  const publicPath = path.join(directory, `${stem}-public.pem`);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
  const privateHandle = await fs.open(privatePath, 'wx', 0o600);
  try { await privateHandle.writeFile(privateKey, 'utf8'); } finally { await privateHandle.close(); }
  try {
    const publicHandle = await fs.open(publicPath, 'wx');
    try { await publicHandle.writeFile(publicKey, 'utf8'); } finally { await publicHandle.close(); }
  } catch (error) {
    await fs.rm(privatePath, { force: true });
    throw error;
  }
  return { privatePath, publicPath };
}

if (require.main === module) generateKeys().then(paths => console.log(`Created a new Ed25519 audit signing key pair.\nPrivate key: ${paths.privatePath}\nPublic key: ${paths.publicPath}\nKeep the private key out of source control and back up the public key for offline verification.`)).catch(error => { console.error(error.code === 'EEXIST' ? 'A signing key file already exists; refusing to overwrite it.' : error.message); process.exitCode = 1; });

module.exports = { generateKeys };
