# Production foundation

The Compose stack provides PostgreSQL and scheduled local backups:

```powershell
Copy-Item .env.example .env
# Set POSTGRES_PASSWORD and the identity/deployment secrets in .env
docker compose up -d postgres backup backup-manifest
```

## Restore drill

Run the isolated recovery drill against a selected scheduled artifact (the latest non-empty supported backup is chosen if omitted):

```powershell
npm run restore-drill:postgres -- --backup backups/daily/agentguard-YYYYMMDD.sql.gz
```

The `backup-manifest` service watches completed SQL gzip artifacts and creates a sibling manifest with the exact compressed artifact's SHA-256 and per-table row counts parsed from its `COPY` sections. The drill verifies that digest and compares restored counts to the manifest. It creates and removes a scratch database; it does not restore into the configured live database. It also verifies every workspace's audit chain and runs a complete approval → claim → completion write workflow on the restored scratch database. A JSON `postgres-cutover-*.json` snapshot is accepted for compatibility and receives exact row-count comparison. The host must have `psql` or Docker Compose CLI for `.sql.gz` restore. The manifest is not signed, so protect it with the backup or add an external trust/signing mechanism. Cleanup success is reported only after the scratch database has actually been dropped; cleanup failure fails the run.

### CI restore drill

`.github/workflows/postgres-restore-drill.yml` runs the same core recovery checks against a disposable PostgreSQL 16 service using synthetic data only. On push, pull request, or manual dispatch it seeds one workspace/company and a hash-chained event, creates a SQL dump and manifest, restores into a scratch database, checks counts and the audit chain, performs an approval → claim → completion write, then verifies scratch cleanup. The workflow is configured; the first successful hosted run is still required as evidence. It does not access production backups or secrets.

## HTTPS production profile

The optional `production` profile builds AgentGuard into a private container and places Caddy in front of it. The app has no published host port, Caddy is the only public entry point, and PostgreSQL stays bound to host loopback. Before activating, set a real `AGENTGUARD_HOST`, `AGENTGUARD_PUBLIC_ORIGIN=https://<host>`, and an exact Google OAuth callback `OIDC_REDIRECT_URI=https://<host>/auth/callback` in `.env`; configure the same callback in Google OAuth Console; point public DNS at the host; and permit inbound TCP 80/443 plus UDP 443 for HTTP/3. Start it with:

```powershell
docker compose --profile production up -d --build postgres backup backup-manifest app caddy
```

Caddy manages public certificates. Production startup validates the canonical HTTPS origin and callback match; sessions and OAuth state cookies are Secure. The proxy sends traffic to `app:3100` on a private Compose network, and Caddy adds HSTS. Verify certificate issuance/renewal and the full sign-in/sign-out flow in staging before client exposure. Local `npm start` on port 3100 remains available outside this profile.

The PostgreSQL runtime store is workspace-scoped by design. Startup prefers the relational `ag_*` tables, and repositories handle normal database writes. PostgreSQL `writeStore()` only refreshes the process cache. Legacy bootstrap paths remain, including compatibility records and SQLite import when no relational data is available; their retirement and a complete write-path audit are planned in [the enterprise roadmap](../ROADMAP.md). Do not treat repository presence as proof that every operation is durable.

Verify the migration without displaying secrets:

```powershell
node --env-file=.env -e "const s=require('./storage');s.initializeStore().then(()=>console.log(s.readStore().schemaVersion))"
```

After upgrading, restart the Node application so it reads schema version 12. SQLite remains the supported local-development fallback when `AGENTGUARD_STORAGE=sqlite`; set `AGENTGUARD_STORAGE=postgres` in staging and production.

## Relational migration

The production migration creates typed PostgreSQL tables for workspaces, memberships, companies, agents, policies, approvals, assessments, incidents, alerts, alert deliveries, and append-only audit events. It is idempotent and reads from the current `agentguard_records` store:

```powershell
node --env-file=.env scripts/migrate-relational-postgres.js
```

The migration prints only table counts; it never prints database credentials or gateway secrets. Keep `agentguard_records` in place until the repository cutover and backup/restore validation are complete.

The repository cutover is staged: membership, company, agent, policy, approval, and dashboard audit reads use relational repositories when PostgreSQL is enabled. Audit appends use `ag_audit_events`. Normal PostgreSQL writes no longer refresh the compatibility mirror; legacy bootstrap code still can. Remaining work includes proving durable acknowledgements, transaction boundaries, and behavior across restarts and multiple instances before removing fallback code.

Audit integrity is enabled with `previous_hash` and `event_hash` columns on `ag_audit_events`. Backfill an existing environment with:

```powershell
node --env-file=.env scripts/backfill-audit-hashes.js
```

Google Workspace OIDC, signed sessions, and application RBAC are supported for `owner`, `admin`, `reviewer`, `operator`, and `viewer` roles. Restrict the verified email domain with `GOOGLE_WORKSPACE_DOMAIN`. TLS should terminate at the deployment reverse proxy; never expose PostgreSQL directly to the public network.

The first successful sign-in by `AGENTGUARD_OWNER_EMAIL` creates a durable owner membership. From then on, use **Workspace access** in AgentGuard to add members or change their roles. `AGENTGUARD_ROLE_MAP` remains only as a migration/bootstrap fallback; remove it after the required people have signed in once.

Set `AGENTGUARD_REQUIRE_AUTH=true` only after Google OAuth credentials and the callback URL have been verified. This redirects unauthenticated dashboard visitors to `/auth/login` and protects `/api/dashboard` with a 401 response.
