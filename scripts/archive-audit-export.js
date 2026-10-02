const { archiveExport } = require('./audit-archive');

if (require.main === module) {
  const [exportPath, trustedKeysPath, archiveDirectory, privateKeyPath, signingKeyId] = process.argv.slice(2);
  if (![exportPath, trustedKeysPath, archiveDirectory, privateKeyPath, signingKeyId].every(Boolean)) {
    console.error('Usage: node scripts/archive-audit-export.js <export.ndjson> <trusted-keyring.json|public-key.pem> <archive-directory> <checkpoint-private-key.pem> <checkpoint-key-id>');
    process.exitCode = 2;
  } else archiveExport(exportPath, trustedKeysPath, archiveDirectory, privateKeyPath, signingKeyId)
    .then(result => console.log(JSON.stringify(result)))
    .catch(error => { console.error(error.message); process.exitCode = 1; });
}
