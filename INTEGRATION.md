# AgentGuard integration API

AgentGuard evaluates an action before an agent performs it. The current service is intended for a trusted local development environment.

## Register and report events

Send POST /api/agent-events when an agent starts reporting. Include stable agent metadata on the first event:

    {
      "agentId": "research-assistant",
      "event": "started",
      "message": "Research job started",
      "actionRef": "job-123",
      "agent": {
        "name": "Research Assistant",
        "team": "Research",
        "tools": ["market-data", "browser"]
      }
    }

## Check an action before execution

Call POST /api/guard/check before each action that needs a control decision. Use a unique actionRef for each attempted action; retries should reuse it.

    {
      "agentId": "research-assistant",
      "actionType": "tool_call",
      "action": "Read a market-data quote",
      "resource": "tool:market-data",
      "actionRef": "job-123:market-data:1"
    }

The response has one of three decisions:

- allow: proceed.
- awaiting_approval: pause and poll GET /api/approvals/{approvalId}. Proceed only after it reports approved.
- block: do not perform the action.

No matching policy means allow, and the decision is written to the activity log.

### StockAgent fleet

StockAgent reports an orchestrator plus these specialist agents to AgentGuard:

- `stockagent` — orchestration and job lifecycle
- `stockagent-planner` — research planning
- `stockagent-fundamental` — fundamental analysis
- `stockagent-technical` — technical analysis
- `stockagent-news` — news research
- `stockagent-review` — evidence and quality review
- `stockagent-risk` — risk review
- `stockagent-final` — report synthesis

Each specialist has its own stable ID, team, tools, health status, and audit identity. The existing `stockagent` policy remains the orchestration gate for a complete research job; specialist-specific policies can target any child ID.

## Policy matching

Policies can target one agent or *, one action type or *, and a resource pattern. Resource patterns support exact values, *, or a trailing wildcard such as tool:*. Higher priority policies win; when priorities tie, block takes precedence over require_approval, which takes precedence over allow.

Policy effects are allow, require_approval, and block. Policy edits increment a version recorded with the audit event.

## Persistence

Local development persists workspace state in `agentguard.sqlite` using Node's built-in SQLite driver. PostgreSQL mode uses workspace-keyed relational tables and repositories for the staged production cutover; the legacy compatibility record store remains while all telemetry ingestion paths are migrated. Run `node --env-file=.env scripts/migrate-relational-postgres.js` before enabling PostgreSQL in a new environment.

## Production security baseline

Set `AGENTGUARD_API_KEY` on the server and the same value on each integration process. AgentGuard then requires `Authorization: Bearer <key>` for agent events and policy checks. A basic per-client rate limit is enabled by default (`AGENTGUARD_RATE_LIMIT=240` requests per minute). User login uses Google Workspace OpenID Connect with `OIDC_ISSUER=https://accounts.google.com` and a verified `GOOGLE_WORKSPACE_DOMAIN`. Workspace membership and RBAC are enforced for dashboard access and configuration actions. Before exposing a multi-company deployment to an untrusted network, validate TLS termination, secret rotation, PostgreSQL backup restores, and completion of the repository cutover.
# Generic agent configuration

Every agent uses the same environment contract; only the values differ per registered agent. Copy `agent.env.example` into the agent project as `.env`, set the AgentGuard API URL, the credential returned during registration, and that agent's generated ID, then start the agent with `AgentGuard.from_environment(...)`.

Required values:

```ini
AGENTGUARD_URL=https://localhost
AGENTGUARD_API_KEY=<agent credential>
AGENTGUARD_AGENT_ID=<registered agent id>
```

Name, team, and tools are configured once during registration and are not repeated in the agent runtime environment. The Stock Agent now follows this pattern in `stock_agent.py`. Cricket, IPO, job, and any future agent should use the same SDK call; they should not hardcode an ID or URL. For a Docker-hosted AgentGuard connecting to an agent on the host, use `http://host.docker.internal:<port>` as the runtime URL where applicable.
