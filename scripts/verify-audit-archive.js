const { verifyArchive, verifyContinuation } = require('./audit-archive');

if (require.main === module) {
  const [checkpointPath, trustedKeysPath, nextExportPath] = process.argv.slice(2);
  if (!checkpointPath || !trustedKeysPath) {
    console.error('Usage: node scripts/verify-audit-archive.js <checkpoint.json> <trusted-keyring.json|public-key.pem> [next-export.ndjson]');
    process.exitCode = 2;
  } else (nextExportPath ? verifyContinuation(checkpointPath, nextExportPath, trustedKeysPath) : verifyArchive(checkpointPath, trustedKeysPath))
    .then(result => console.log(JSON.stringify(result)))
    .catch(error => { console.error(error.message); process.exitCode = 1; });
}
