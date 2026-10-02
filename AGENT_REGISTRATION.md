# AgentGuard agent registration guide

This guide describes the standard plug-and-play process for onboarding any AI
agent, regardless of framework or programming language.

## 1. Register the agent

Open **Agents → Register Agent** and complete all fields:

- **Company:** select an existing company or create a new company.
- **Agent name:** human-readable name shown in AgentGuard.
- **Team:** owning team or business function.
- **Tools:** tools the agent is expected to use, entered as names such as
  `market-data`, `news-search`, or `portfolio-data`.
- **Agent type/framework/model/version:** optional metadata used for governance
  and assessment.
- **Runtime URL:** optional health/status URL when managed URL monitoring is used.
- **Parent agent:** optional; leave empty for a standalone agent.
- **Risk tier, data class, autonomy:** governance metadata used by assessment.

AgentGuard generates the numeric agent ID. Do not invent or change it. The
company ID is also managed by AgentGuard; use the exact ID shown beside the
company name when configuring an external connector.

## 2. Start the connection

Open the new agent and select **Start connection**. AgentGuard returns a gateway
credential once. Copy it immediately and store it in the agent's secret store.

After the first credential is issued, clicking Start again reuses the existing
credential. It does not rotate the key. Rotate only from the explicit credential
rotation control, then update the agent configuration.

Never commit the credential to Git, paste it into logs, or put it in a browser
URL.

## 3. Configure the external agent

The external agent needs four values:

```text
AGENTGUARD_URL=https://<agentguard-host>
AGENTGUARD_AGENT_ID=<numeric-agent-id>
AGENTGUARD_COMPANY_ID=<company-id>
AGENTGUARD_API_KEY=<gateway-credential>
```

For local HTTP development:

```bash
export AGENTGUARD_URL=http://localhost:3100
export AGENTGUARD_AGENT_ID=1234
export AGENTGUARD_COMPANY_ID=example-company
export AGENTGUARD_API_KEY='copy-the-credential-from-start-connection'
python your_agent.py
```

For the Docker staging proxy:

```bash
export AGENTGUARD_URL=https://localhost
export AGENTGUARD_AGENT_ID=1234
export AGENTGUARD_COMPANY_ID=example-company
export AGENTGUARD_TLS_VERIFY=false  # local self-signed certificate only
export AGENTGUARD_API_KEY='copy-the-credential-from-start-connection'
python your_agent.py
```

Production must use a trusted HTTPS certificate; do not disable TLS verification.

## 4. Send standard lifecycle events

Use the AgentGuard Node or Python SDK where possible. A minimal integration must
report connection, running work, completion, and failure:

```text
started       agent connected
running       work began
completed     work finished
failed        work failed
```

Heartbeats prove liveness but are not audit activity. AgentGuard uses activity
events to show an agent as running and transitions it to idle after the configured
activity timeout. A failed heartbeat can mark an agent failed/offline.

For Python agents in this repository, `agent_runtime.py` provides the reusable
configuration and lifecycle loop. Copy `agents/stock_agent.py`, rename it for the new
agent, and replace only its `*_workload()` function. The IPO or Cricket agent
should keep the same `run_agent(...)` wrapper and change only the business logic.

## 5. Verify onboarding

After starting the agent, confirm:

1. AgentGuard shows **Connected**.
2. A running event changes the status to **Running**.
3. The task, message, and timestamps appear in Activity.
4. A completion event returns the agent to **Idle** after the configured grace period.
5. The agent detail page shows the correct company and agent ID.
6. No credential appears in the UI, API response, audit log, or export.

If the connection fails, check the URL scheme/port, exact numeric agent ID, exact
company ID, credential, staging TLS setting, and the gateway response status.

## 6. Governance expectations

Registration metadata is part of the agent's governance profile. Changes to
company, parent, risk tier, data class, or autonomy require reassessment. Changes
to tools, runtime URL, framework, model, agent type, or version are recorded as
pending assessment changes and are reviewed as a batch.

Register each real agent separately. Do not reuse one agent ID or credential for
multiple companies or runtimes.
