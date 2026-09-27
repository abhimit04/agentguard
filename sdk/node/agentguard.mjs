export class AgentGuard {
  static fromEnvironment(options = {}) {
    const tools = (process.env.AGENTGUARD_AGENT_TOOLS || '').split(',').map(tool => tool.trim()).filter(Boolean);
    return new AgentGuard({
      id: process.env.AGENTGUARD_AGENT_ID,
      name: process.env.AGENTGUARD_AGENT_NAME,
      team: process.env.AGENTGUARD_AGENT_TEAM,
      tools,
      ...options,
    });
  }

  constructor({ id, name, team, tools = [], url = process.env.AGENTGUARD_URL || 'http://localhost:3100', heartbeatMs = 30000 }) {
    if (!id) throw new Error('AgentGuard requires an agent id');
    this.agent = { id, ...(name || team || tools.length ? { name, team, tools } : {}) };
    this.url = url.replace(/\/$/, '');
    this.heartbeatMs = heartbeatMs;
    this.apiKey = process.env.AGENTGUARD_API_KEY || '';
    this.timer = null;
  }

  async request(path, options = {}) {
    const response = await fetch(`${this.url}${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...(this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}), ...(options.headers || {}) }, body: options.body && JSON.stringify(options.body) });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `AgentGuard request failed (${response.status})`);
    return payload;
  }

  async report(event, message, actionRef = null) {
    const body = { agentId: this.agent.id, event, message, actionRef };
    if (this.agent.name && this.agent.team) body.agent = this.agent;
    return this.request('/api/agent-events', { method: 'POST', body });
  }

  async heartbeat() {
    try { await this.report('heartbeat', `${this.agent.name} is online`); return true; }
    catch (error) { this.onError?.(error); return false; }
  }

  async start() {
    await this.report('started', `${this.agent.name} connected`);
    await this.heartbeat();
    this.timer = setInterval(() => this.heartbeat(), this.heartbeatMs);
    return this;
  }

  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; }

  async check(actionType, action, actionRef, resource = '*') {
    return this.request('/api/guard/check', { method: 'POST', body: { agentId: this.agent.id, agent: this.agent, actionType, action, actionRef, resource } });
  }

  async waitForApproval(approvalId, intervalMs = 2500) {
    for (;;) {
      const result = await this.request(`/api/approvals/${encodeURIComponent(approvalId)}`);
      if (result.status !== 'pending') return result.status;
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
  }
}
