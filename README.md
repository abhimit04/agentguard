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
- Policy effects: allow, require approval, or block, with policy versions, action references, tool/resource patterns, and a no-side-effect simulator.
- Approval lifecycle with exact action/policy matching, reviewer identity, and configurable automatic expiry.
- Audit logging that excludes heartbeat noise and records agent activity, policy decisions, connector events, and governance changes.
- Tamper-evident PostgreSQL audit chain with per-workspace previous-hash links and SHA-256 event hashes.
- SQLite local fallback and PostgreSQL production persistence with scheduled Docker backups.
- Coalesced PostgreSQL persistence to prevent telemetry bursts from exhausting Node.js memory.
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
docker compose up -d postgres backup
npm start
```

Use `AGENTGUARD_STORAGE=sqlite` for local mode. PostgreSQL is selected when `AGENTGUARD_STORAGE=postgres` or `DATABASE_URL` is configured.

## PostgreSQL migration state

### Durable governed execution

Approval-controlled actions use a PostgreSQL execution ledger. Agents call
`POST /api/guard/check`, wait for approval when required, and atomically claim
the exact approved action with `POST /api/guard/executions/claim`. Only the
first claim receives an execution grant; retries are suppressed. After running,
the agent reports the outcome to `POST /api/guard/executions/complete`.
Execution state and its audit evidence are committed together and survive a
server restart.

Run the isolated proof against a disposable PostgreSQL database:

```powershell
node --env-file=.env scripts/test-governed-execution-postgres.js
```

The repository cutover is staged. Workspace memberships, companies, agents, policies, approvals, and dashboard audit reads use relational PostgreSQL repositories. New audit events append to `ag_audit_events`; the compatibility record store remains while legacy telemetry paths are migrated.

The active data set has been migrated and verified: 1 workspace, 6 companies, 47 agents, 2 policies, 11 approvals, and 11,351 audit events.

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

Verify that the latest PostgreSQL backup is genuinely restorable. The drill creates an isolated temporary database, restores every production table, checks row counts and the audit hash chain, and removes the temporary database without changing live data:

```powershell
npm run backup:postgres
npm run restore-drill:postgres
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

## Current hardening tranche

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

Next priorities are tool-level permission grants and spend limits, expiring approvals, policy simulation, incident/case management, verified server-side export packages, PostgreSQL restore drills, and TLS/reverse-proxy deployment validation.
