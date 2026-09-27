# AgentGuard test agents

These are two independent local agents for exercising the AgentGuard integration without external model credentials.

Start AgentGuard first, then run each agent in a separate terminal:

```powershell
node examples/test-agents/market-research-agent.mjs
node examples/test-agents/invoice-ops-agent.mjs
```

To start five independent demo agents using one shared integration implementation:

```powershell
npm run agents:five
```

The five IDs are `demo-cricket-agent`, `demo-market-agent`, `demo-invoice-agent`, `demo-support-agent`, and `demo-hr-agent`. Leave that terminal running to keep their heartbeats active; press Ctrl+C to stop them.

For a production-style demo with five separate worker processes, run:

```powershell
node examples/test-agents/production-demo.mjs
```

The supervisor uses one shared worker implementation and injects each agent's identity through environment variables, matching a container or process-manager deployment.

Each agent registers itself, emits a lifecycle event, and calls `/api/guard/check` before its simulated action. The scripts never bypass a decision: `allow` proceeds, `awaiting_approval` pauses, and `block` stops.

You can use the AgentGuard UI to create policies for either ID:

- `market-research-agent`
- `invoice-ops-agent`

For example, target `market-research-agent` with action type `research`, resource `ticker:*`, and effect `require_approval`.
