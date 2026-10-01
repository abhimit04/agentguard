# AgentGuard

AgentGuard is an AI-agent control plane for enterprise teams. It provides a central inventory, runtime health, activity and audit visibility, policy guardrails, approvals, risk assessments, and workspace-scoped access management for agents built in any language or framework.

## Current capabilities

- Google Workspace OIDC login with signed sessions and logout.
- Workspace isolation on companies, agents, policies, approvals, assessments, memberships, and audit events.
- RBAC roles: `owner`, `admin`, `reviewer`, `operator`, and `viewer`.
- Workspace Access UI for adding, changing, and removing members.
- Agent registration with generated four-digit IDs, company assignment, parent/child classification, archive/restore, and managed runtime URLs.
- Generic gateway, SDK, sidecar, OpenTelemetry, and HTTP runtime integration paths.
- Runtime states including registered, connected/healthy, running, idle, failed, offline, and archived.
- Policy effects: allow, require approval, or block, with policy versions, action references, tool/resource patterns, per-action limits, daily cumulative budgets, and a no-side-effect simulator.
- Approval lifecycle with exact action/policy matching, reviewer identity, and configurable automatic expiry.
- Audit logging that excludes heartbeat noise and records agent activity, policy decisions, connector events, and governance changes.
- Tamper-evident PostgreSQL audit chain with per-workspace previous-hash links and SHA-256 event hashes.
- SQLite local fallback and PostgreSQL production persistence with scheduled Docker backups.
- Coalesced PostgreSQL persistence to prevent telemetry bursts from exhausting Node.js memory.
- Shared PostgreSQL ingestion limits with separate company and agent telemetry quotas to isolate noisy neighbours.
- Incident management and an in-app alert center, with optional signed webhook delivery and recorded delivery outcomes.
- Server-generated compliance evidence packages with date scoping, credential scrubbing, audit-chain anchors, and SHA-256 integrity metadata.

## Run locally

```powershell
npm install
npm run ui       # Vite development UI on http://localhost:5173
npm start        # AgentGuard server on http://localhost:3100
```

For production-like infrastructure:

```powershell
Copy-Item .env.example .env
# Set POSTGRES_PASSWORD and the Google/JWT/API secrets
docker compose up -d postgres backup backup-manifest
npm start
```

### Production HTTPS profile

The optional Compose production profile runs AgentGuard in a private app container behind Caddy. Unlike the local `npm start` workflow, the app container has no published host port; Caddy is the only public HTTP(S) entry point, and PostgreSQL remains loopback-bound on the host. To activate it, first set a real DNS name in `.env` (`AGENTGUARD_HOST`, `AGENTGUARD_PUBLIC_ORIGIN`, and the exact matching `OIDC_REDIRECT_URI=https://<host>/auth/callback`), allow inbound TCP 80/443 and UDP 443, and register that callback in Google OAuth Console. Then run:

```powershell
docker compose --profile production up -d --build postgres backup backup-manifest app caddy
```

Caddy obtains and renews the public certificate automatically. Production startup rejects a missing/non-HTTPS public origin or a callback URL whose host/path does not match. The app sets Secure session and OAuth cookies in production; Caddy adds HSTS and standard response headers. Keep `3100` closed to external clients. The actual DNS, firewall, Google OAuth round-trip, certificate issuance/renewal, and host-specific Docker build still need to be verified in the client's staging environment; the profile is not a substitute for those deployment checks.

Use `AGENTGUARD_STORAGE=sqlite` for local mode. PostgreSQL is selected when `AGENTGUARD_STORAGE=postgres` or `DATABASE_URL` is configured.

### Telemetry fair-use limits

AgentGuard applies a general integration limit plus independent telemetry limits
per company and per agent. In PostgreSQL mode the limits use shared atomic
minute buckets, so every application instance applies the same capacity rules.
The defaults are `240` requests/minute per caller or agent and `2,400`
requests/minute per company. Configure `AGENTGUARD_RATE_LIMIT`,
`AGENTGUARD_AGENT_RATE_LIMIT`, and `AGENTGUARD_COMPANY_RATE_LIMIT` for the
deployment. Rejections return HTTP `429` with `Retry-After: 60`; telemetry
bodies and batches are also bounded before ingestion.

## PostgreSQL migration state

### Durable governed execution

Approval-controlled actions use a PostgreSQL execution ledger. Agents call
`POST /api/guard/check`, wait for approval when required, and atomically claim
the exact approved action with `POST /api/guard/executions/claim`. Only the
first claim receives an execution grant; retries are suppressed. After running,
the agent reports the outcome to `POST /api/guard/executions/complete`.
Execution state and its audit evidence are committed together and survive a
server restart.

### Policy budgets

Each policy can set optional limits for a single action (`Maximum tokens` and
`Maximum cost`) and cumulative limits for one agent on the current UTC day
(`Daily actions`, `Daily tokens`, and `Daily cost`). AgentGuard reserves daily
capacity in PostgreSQL before an allow or approval-gated action progresses, so
concurrent requests cannot overspend the same limit. A reviewer denial or an
approval expiry releases that action's reservation; an approved or directly
allowed action remains counted for the day. Token and cost limits require the
agent to send an estimate with its governed action request.

The **Simulate a decision** dialog is read-only. For a policy with a daily
budget, it displays the current reserved usage and the projected usage for the
proposed action, including whether that action would be blocked. It never
reserves capacity or changes an agent's runtime state.

### Assessment dependency records

Editing or creating a policy records a **policy dependency** change on the
approved assessments of agents the policy applies to. This is an operational
change: it preserves the approved assessment and adds a visible pending-change
record with the policy ID, version, effect, action type, and resource pattern.
It gives reviewers the policy context at the next assessment review without
forcing a low-signal reassessment for every routine policy revision.

If a claim remains unresolved for five minutes, reviewers see it under
**Uncertain executions** on the overview. Verify the downstream idempotency
record or other authoritative evidence before choosing **Confirm completed** or
**Confirm not executed**. Reconciliation is workspace-scoped, reviewer-only,
and audited. It never automatically retries an action: a confirmed no-effect
attempt is closed, and any retry must be a new policy-checked action. The
generic connector cannot independently prove an external system's state.

Run the isolated proof against a disposable PostgreSQL database:

```powershell
node --env-file=.env scripts/test-governed-execution-postgres.js
```

The repository cutover is staged. Workspace memberships, companies, agents, policies, approvals, and dashboard audit reads use relational PostgreSQL repositories. New audit events append to `ag_audit_events`. In PostgreSQL mode, `writeStore()` updates the process cache rather than the compatibility table; legacy bootstrap paths remain. The remaining write-path and transaction guarantees are tracked in [ROADMAP.md](ROADMAP.md).

A previously recorded migration reported 1 workspace, 6 companies, 47 agents, 2 policies, 11 approvals, and 11,351 audit events. These are historical migration counts, not current deployment verification.

```powershell
node --env-file=.env scripts/migrate-relational-postgres.js
```

Restart the Node process after code or migration changes.

## Integration model

Agents can connect through the language-neutral gateway envelope, Python/Node SDKs, the universal OpenTelemetry connector, a company gateway, or a managed JSON runtime URL. New agents need a stable AgentGuard identity and authenticated telemetry; the dashboard does not require agent-specific UI code.

See [INTEGRATION.md](INTEGRATION.md), [sdk/README.md](sdk/README.md), and [connector/README.md](connector/README.md).

## Verification

```powershell
$env:AGENTGUARD_REQUIRE_AUTH='false'
node --test
node node_modules/vite/bin/vite.js build
```

The suite covers workspace isolation, RBAC membership behavior, gateway credentials, telemetry state transitions, heartbeat suppression, managed connectors, and audit behavior.

The `backup-manifest` Compose service watches for completed non-empty scheduled `.sql.gz` files and writes a sibling manifest containing the artifact SHA-256 and row counts extracted from that exact dump. The restore drill accepts both AgentGuard JSON snapshots and Docker's scheduled `.sql.gz` backups. It verifies the sidecar digest, restores into a randomly named scratch database, compares table counts, verifies each workspace's audit chain, runs an approval-to-execution governed write smoke test, then reports actual scratch-database cleanup. Zero-byte `*-latest.sql.gz` aliases are ignored. Select a backup explicitly when needed:

```powershell
npm run restore-drill:postgres -- --backup backups/daily/agentguard-YYYYMMDD.sql.gz
# or, for the compatibility JSON format:
npm run restore-drill:postgres -- --backup backups/postgres-cutover-YYYY-MM-DDTHH-MM-SS-sssZ.json
```

For `.sql.gz`, the host needs either `psql` on `PATH`, Docker Compose CLI for the local Postgres service, or an explicitly configured `AGENTGUARD_RESTORE_DOCKER_CONTAINER`. New manifests can be Ed25519-signed; unsigned historical manifests remain a migration exception and should not be treated as independently authenticated provenance.

The `PostgreSQL restore drill` GitHub Actions workflow provisions an isolated PostgreSQL 16 service, seeds synthetic workspace/company/audit data, creates a SQL dump and manifest, then uses the same scratch-database restore, audit-chain verification, governed-write smoke, and cleanup checks. It runs on push, pull request, or manual dispatch. Its first hosted run passed on 2026-10-01 and it uses no production backup or credentials.

For a staging HTTPS deployment behind Caddy, verify the public proxy, headers, HTTP-to-HTTPS redirect, and Google callback configuration with:

```bash
npm run smoke:proxy
```

## Audit integrity

Existing PostgreSQL audit records were backfilled into a per-workspace SHA-256 hash chain. New events append with `previous_hash` and `event_hash`; audit records are never updated by normal application activity. To repeat the idempotent backfill in a newly migrated environment:

```powershell
node --env-file=.env scripts/backfill-audit-hashes.js
node --env-file=.env scripts/verify-audit-chain.js
```

## Alert delivery

AgentGuard always creates an in-app alert when an automatic governance incident opens. To deliver the same alert to an external notification relay, set these values in `.env` and restart the server:

```ini
AGENTGUARD_ALERT_WEBHOOK_URL=https://your-notification-relay.example/agentguard
AGENTGUARD_ALERT_WEBHOOK_TOKEN=use-a-random-secret-with-at-least-32-characters
```

The relay receives a JSON event named `agentguard.alert.opened`. Every request is signed in `X-AgentGuard-Signature` as `sha256=<HMAC-SHA256 of the raw body>`. Delivery outcomes are retained in PostgreSQL; a failed delivery can be retried from **Alerts**. Do not configure a Slack/Teams URL directly unless its receiver can verify the signature or is protected behind your own relay.

## Compliance evidence

Owners, administrators, and reviewers can download a server-generated evidence package from **Activity → Export evidence package**. The JSON bundle includes the agent inventory, policies, approvals, assessments, incidents, alerts, delivery records, and up to 10,000 audit events for the selected period. Agent credentials and runtime authorization headers are removed. The manifest includes audit-chain boundary hashes and a SHA-256 digest over the compact `{manifest,evidence}` payload.

Before the deterministic-chain migration, take a database snapshot. The migration preserves event payloads while replacing legacy hashes with canonical, reproducible hashes:

```powershell
node --env-file=.env scripts/backup-postgres.js
node --env-file=.env scripts/migrate-audit-chain.js
node --env-file=.env scripts/verify-audit-chain.js
```

The Activity page also provides **Verify chain** and **Load older audit events**. Verification is resumable in bounded pages; results report the checked count, sequence range, head hash, and first detected break. The authenticated `GET /api/audit/verify` endpoint accepts `limit` (up to 10,000) and a signed continuation `cursor`. `GET /api/audit/events` uses keyset pagination against a fixed sequence ceiling; its opaque cursor is bound to the active workspace. Cursors use `AGENTGUARD_AUDIT_CURSOR_SECRET` when configured, or `JWT_SECRET` otherwise. The verifier checks the chain currently stored in PostgreSQL; an independently retained signed head is still needed to prove that a valid suffix was not truncated.

The existing JSON evidence package remains available for a full JSON snapshot. For an independently verifiable audit segment, create an Ed25519 key pair once:

```powershell
node scripts/generate-audit-signing-key.js
```

Set `AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_FILE=./secrets/audit-signing-private.pem` and a stable `AGENTGUARD_AUDIT_SIGNING_KEY_ID` in `.env`, then restart the server. The private key is git-ignored; distribute the generated public key through a trusted channel. Download a segment from `GET /api/evidence/audit.ndjson`; optional `fromSequence` and `toSequence` parameters select its inclusive workspace sequence range. Exports are bounded to 10,000 events and refuse oversized segments rather than truncate. Verify the downloaded file offline:

```powershell
node scripts/verify-audit-export.js .\agentguard-audit-default-1-100.ndjson .\audit-signing-public.pem
```

For routine signing-key rotation, generate a fresh, never-reused key ID without overwriting an earlier pair, for example `node scripts/generate-audit-signing-key.js agentguard-2026-q4`. Add that new public key to the verifier's trusted keyring (keep old entries so earlier exports remain verifiable):

```json
{
  "format": "agentguard-audit-keyring-v1",
  "keys": {
    "agentguard-local-2026": "./audit-signing-public.pem",
    "agentguard-2026-q4": "./audit-signing-agentguard-2026-q4-public.pem"
  }
}
```

Paths in the keyring are relative to the keyring file. Configure the server with the new private-key path and matching key ID, restart it, and verify a fresh export before retiring the old private key. Keep the trusted keyring and each public key in a controlled distribution channel; a keyring supplied by the same untrusted party as an export does not establish trust. Verify with `node scripts/verify-audit-export.js <export.ndjson> <trusted-keyring.json>`. The verifier still accepts one PEM public key for legacy/single-key use. Rotation is operator-managed: this does not automate secret storage, synchronized rollout across instances, or revocation of a compromised historical key.

To retain a signed boundary, archive an already downloaded and verified segment. The archive command copies the export without overwriting an existing file, writes a signed checkpoint beside it, and verifies both. Use a trusted public key or keyring that includes the checkpoint signing key ID:

```powershell
$archived = node scripts/archive-audit-export.js .\agentguard-audit-default-1-100.ndjson .\trusted-keys.json .\audit-archive .\secrets\audit-signing-private.pem agentguard-local-2026 | ConvertFrom-Json
node scripts/verify-audit-archive.js ($archived.checkpointPath) .\trusted-keys.json
node scripts/verify-audit-archive.js ($archived.checkpointPath) .\trusted-keys.json .\agentguard-audit-default-101-200.ndjson
```

The last command verifies the archived file, checkpoint signature, and hash link into the next export. Keep archive files and checkpoints in independently controlled, immutable storage; a local folder alone does not prevent later replacement or deletion. This workflow does not prune PostgreSQL audit rows. Tenant retention policies and an authorized archive/restore gate must be implemented before any pruning is enabled.

Workspace legal holds are available in the Audit log once the PostgreSQL app is restarted with the latest schema. Owners and admins can create a hold with a reason and optional case reference; only owners can release it, with a release reason. All workspace members can see hold status. The record and its hash-chained audit event commit together. The same controls are exposed through `GET` and `POST /api/audit/legal-holds` and `POST /api/audit/legal-holds/{id}/release`. The database does not have an audit-pruning operation, so an active hold cannot be bypassed by an AgentGuard retention job. Before a pruning feature is introduced, it must check active holds inside the deletion transaction, verify the archive and restore, and retain the signed checkpoint independently.

`npm run test:legal-holds-postgres` exercises hold authorization and audit rollback, then restores a JSON snapshot containing an active and a released hold into a second disposable PostgreSQL database. It checks the restored hold states and audit chain and removes both scratch databases. Scheduled SQL backup restoration remains a separate deployment check.

Workspace admins and owners can now set an audit retention period of 30–3650 days in the Activity log. `GET /api/audit/retention` returns the configured period, cutoff, count of older events, active hold count, and cleanup blockers; `PUT /api/audit/retention` requires the current version and records its change in the hash-chained audit log atomically. This is a **preview only**: audit cleanup remains disabled until archive, restore, and independently retained checkpoint evidence can be enforced in the same deletion transaction. A legal hold appears as an explicit blocker. The disposable PostgreSQL legal-hold test also verifies retention roles, isolation, stale-version rejection, audit rollback, and JSON backup/restore of settings.

## Current hardening tranche

Agent profiles now include a versioned AI risk assessment. Owners and admins can record purpose, impact, privacy/bias/security risk, human oversight, rationale, evidence references, owner, and review date. AgentGuard calculates an explainable `agentguard-risk-v1` score and stores every save in `ag_assessment_revisions`; the current record, immutable revision, and hash-chained audit event commit atomically. The Agent Details page shows each factor's contribution so reviewers can see why the score increased or decreased. Use `GET /api/agents/{id}/assessment/history` to retrieve the workspace-scoped revision history. The score supports governance prioritization and is not legal certification.

Approved assessments with a past review date are detected by the background governance sweep. AgentGuard records one `assessment.review_due` event, incident, in-app alert, and durable webhook notification per assessment version. Creating a new approved revision establishes a new review cycle; repeated sweeps do not duplicate the same reminder.

Approved assessments also receive one advance reminder per version before their review date. The default window is 7 days and can be changed from 1–90 days with `AGENTGUARD_ASSESSMENT_REMINDER_DAYS`. An advance reminder creates hash-chained evidence, an in-app alert, and a durable webhook delivery, but not an incident; an incident is created only after the review becomes overdue.

Assessment-relevant changes use two tiers. Structural governance changes—company, parent, risk tier, data classification, or autonomy—immediately change the current assessment to `review_required`. Operational changes—tools, runtime URL, agent type, framework, model, or deployed version—are accumulated as pending changes and audited without invalidating an approved assessment. The Agent Details page shows the pending count and lets a reviewer start a review when the combined change is material. Saving a new assessment revision clears the pending batch. Agent updates, assessment state, and audit evidence commit together; previous reviewer revisions remain immutable.

### Agent changes that require reassessment

AgentGuard automatically changes an existing assessment to **Review required** when any of these hard governance properties change:

- `companyId`: the agent moves to another company or tenant-owned operating context.
- `parentId`: the agent becomes standalone, gains a parent, or moves beneath a different parent agent.
- `riskTier`: the registered operational risk classification changes.
- `dataClass`: the agent starts handling a different data classification (`public`, `internal`, `confidential`, or `restricted`).
- `autonomy`: the agent changes between assistive, supervised, and autonomous operation.

The following soft changes are recorded and batched for the next review without immediately changing an approved assessment's status:

- `tools`: additions and removals are recorded separately rather than as one opaque list change.
- `runtimeUrl`: the external runtime/API endpoint changes.
- `agentType`: the registered operating purpose/type changes.
- `framework`: the orchestration framework or runtime implementation changes.
- `model`: the configured model or provider deployment changes.
- `version`: the deployed agent/model version changes.

The review flag does not rewrite or delete the last approved revision. It updates the current assessment workflow state, records the exact changed property names in the agent-update audit event, and creates a separate `assessment.review_required` audit event. An Owner or Admin should select **Review now**, reconsider the ratings and evidence, select **Approved**, and save a new immutable revision.

Routine liveness changes—heartbeat, connected/running/idle state, last-seen time—and display-only changes such as the agent name or team do not currently trigger reassessment. Archiving or restoring an agent also does not create a new assessment revision automatically. Model and policy dependency changes are still tracked as future reassessment triggers in the roadmap.

- Approval lookup is PostgreSQL-backed and reviewer decisions are atomic.
- Audit appends are transactionally serialized per workspace and API ingestion waits for durable writes.
- OAuth state and user sessions are signed and stateless across restarts and multiple instances.
- Production startup fails closed when authentication, PostgreSQL, or secret configuration is unsafe.
- Failed heartbeats override stale running state and heartbeats no longer extend task activity.
- Agent profiles distinguish monitoring-only, telemetry-connected, and policy-enforced coverage.
- Dashboard governance counts use explicit policy/approval decisions, with CSV audit export.
- Managed runtime polling rejects redirects and private-address targets unless explicitly allowlisted.
- Policy simulation lets administrators test `tool.call` / `tool:<name>` and other action-resource combinations before deployment.

## Next enterprise work

The first repository-durability tranche now commits PostgreSQL telemetry state, retry receipts, audit events, and telemetry incidents together. See [WRITE_PATH_INVENTORY.md](WRITE_PATH_INVENTORY.md) for route coverage, remaining transaction gaps, and upgrade details. Run `npm run test:telemetry-postgres` for the isolated failure/isolation/restart proof. Identified retries require a stable `eventId`; tool permissions are unchanged.

The consolidated [enterprise roadmap](ROADMAP.md) is the source of truth for priorities, source-code findings, dependencies, and acceptance criteria. Start with repository-backed writes and durable audit acknowledgements, followed by a complete governed-execution proof, PostgreSQL-verified signed audit export and retention checkpoints, drills using actual scheduled backups, and HTTPS deployment validation. Comprehensive ingestion limits are a production gate; simulation, approval notifications, versioned risk scoring, verified coverage, and spending controls build on those foundations. Tool-permission changes are on hold.

PostgreSQL SQL backup manifests can be independently signed with Ed25519. Set `AGENTGUARD_BACKUP_MANIFEST_SIGNING_PRIVATE_KEY_FILE` and `AGENTGUARD_BACKUP_MANIFEST_SIGNING_KEY_ID` when creating manifests, and keep the matching public key outside the backup directory in `AGENTGUARD_BACKUP_MANIFEST_PUBLIC_KEY_FILE`. The restore drill verifies a signature when one is present; unsigned legacy manifests remain readable during the migration window, but new production backups should be signed.

Gateway and integration requests have bounded JSON bodies (`AGENTGUARD_MAX_BODY_BYTES`, default 1 MB) and bounded telemetry batches (maximum 500 envelopes). The local limiter is keyed by route plus a hashed credential/agent/IP identity and counts rejected requests, but it is process-local. Multi-instance production deployments must add a shared workspace/company/agent-aware limiter before claiming overload isolation.
