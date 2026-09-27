const AGENTGUARD_URL = process.env.AGENTGUARD_URL || 'http://localhost:3100';

export async function agentRequest(path, options = {}) {
  const response = await fetch(`${AGENTGUARD_URL}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `AgentGuard request failed (${response.status})`);
  return payload;
}

export async function registerAndReport(agent) {
  return agentRequest('/api/agent-events', {
    method: 'POST',
    body: JSON.stringify({
      agentId: agent.id,
      event: 'started',
      message: `${agent.name} connected for a test run`,
      agent: { name: agent.name, team: agent.team, tools: agent.tools },
    }),
  });
}

export async function checkAction(agent, actionType, action, actionRef, resource) {
  return agentRequest('/api/guard/check', {
    method: 'POST',
    body: JSON.stringify({ agentId: agent.id, agent: agent, actionType, action, actionRef, resource }),
  });
}

export async function report(agent, event, message, actionRef) {
  return agentRequest('/api/agent-events', {
    method: 'POST',
    body: JSON.stringify({ agentId: agent.id, event, message, actionRef, agent }),
  });
}

export function waitForApproval(approvalId) {
  return new Promise(async resolve => {
    for (;;) {
      const status = await agentRequest(`/api/approvals/${approvalId}`);
      if (status.status !== 'pending') return resolve(status.status);
      await new Promise(wait => setTimeout(wait, 2500));
    }
  });
}
