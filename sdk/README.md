# AgentGuard SDK

Agents only need to configure identity once. The SDK registers them, sends heartbeats, reports lifecycle events, checks actions against policies, and polls approvals.

## Node.js

```js
import { AgentGuard } from './sdk/node/agentguard.mjs';
const guard = await new AgentGuard({ id: 'cricket-agent', name: 'CricketAgent', team: 'Cricket', tools: ['cricbuzz'] }).start();
const decision = await guard.check('tool_call', 'Read the latest score', `score-${Date.now()}`, 'tool:cricbuzz');
```

For a large fleet, use the same startup code everywhere and provide identity through environment variables:

```js
import { AgentGuard } from './sdk/node/agentguard.mjs';
const guard = await AgentGuard.fromEnvironment().start();
```

Each deployment only supplies its own values:

```env
AGENTGUARD_AGENT_ID=market-research-agent
AGENTGUARD_AGENT_NAME=Market Research Agent
AGENTGUARD_AGENT_TEAM=Growth intelligence
AGENTGUARD_AGENT_TOOLS=Market data,Web search
AGENTGUARD_URL=http://localhost:3100
```

## Python

```python
from sdk.python.agentguard_sdk import AgentGuard
guard = AgentGuard(id='cricket-agent', name='CricketAgent', team='Cricket', tools=['cricbuzz']).start()
decision = guard.check('tool_call', 'Read the latest score', 'score-123', 'tool:cricbuzz')
```

Python agents can use the same environment-only pattern:

```python
guard = AgentGuard.from_environment().start()
```
