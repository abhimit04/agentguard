# AgentGuard protected staging recovery drill

This runbook is the next release gate after the local and GitHub restore checks. It must use a protected PostgreSQL backup and an isolated staging database; it must not run against the live production database.

## Prerequisites

- PostgreSQL client access to a disposable staging database.
- A completed `.sql.gz` backup and its `.manifest.json` sidecar.
- `AGENTGUARD_BACKUP_SIGNING_PUBLIC_KEY` configured outside the backup directory.
- `DATABASE_URL` pointed at the disposable restore database.
- `AGENTGUARD_STORAGE=postgres`.

## Procedure

1. Copy the backup and manifest into a staging-only working directory. Do not modify the source artifact.
2. Verify the manifest before restore:

   ```text
   node scripts/postgres-backup-manifest.js --backup <backup.sql.gz>
   ```

   The restore drill verifies the signed manifest against the independently retained public key. Stop if the digest, signature, or table counts do not match.

3. Restore into a uniquely named scratch database using the restore drill:

   ```text
   node scripts/restore-drill-postgres.js --backup <backup.sql.gz>
   ```

4. Confirm the report shows:

   - every required relational table present;
   - manifest counts matching restored counts;
   - every workspace audit chain verified;
   - approval → execution smoke test passed;
   - scratch database cleanup succeeded.

5. Save the backup, manifest, restore report, verifier output, and timestamps as the staging evidence package. Do not treat backup existence alone as recovery evidence.

## Failure handling

- A missing table, count mismatch, unsigned production manifest, broken audit link, failed governed write, or failed cleanup is a failed drill.
- Preserve the report and database identifier for investigation; do not retry by overwriting the same scratch database.
- Alert the on-call owner and record the failure in the release evidence log.

## Acceptance

The staging gate is accepted only when the complete procedure succeeds twice: once from the scheduled backup path and once after an intentionally interrupted restore. The interrupted run must clean up safely and must not alter the source backup or the live database.
