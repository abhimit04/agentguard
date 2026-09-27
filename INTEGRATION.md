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

AgentGuard persists workspace state in `agentguard.sqlite` using Node's built-in SQLite driver. On the first startup after this migration, the existing `data.json` is imported automatically. The JSON file is retained as a migration backup; ongoing writes use SQLite.

## Production security baseline

Set `AGENTGUARD_API_KEY` on the server and the same value on each integration process. AgentGuard then requires `Authorization: Bearer <key>` for agent events and policy checks. A basic per-client rate limit is enabled by default (`AGENTGUARD_RATE_LIMIT=240` requests per minute). The planned user login uses Google Workspace OpenID Connect with `OIDC_ISSUER=https://accounts.google.com` and a verified `GOOGLE_WORKSPACE_DOMAIN`. For a multi-company deployment, add user authentication, workspace isolation, TLS termination, secret rotation, and PostgreSQL before exposing it to an untrusted network.
