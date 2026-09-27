const config = {
  controlPlane: (process.env.AGENTGUARD_URL || 'http://localhost:3100').replace(/\/$/, ''),
  companyId: process.env.AGENTGUARD_COMPANY_ID || '',
  credential: process.env.AGENTGUARD_GATEWAY_CREDENTIAL || '',
  pollMs: Math.max(5000, Number(process.env.AGENTGUARD_CONFIG_POLL_MS || 10000)),
  heartbeatMs: Math.max(5000, Number(process.env.AGENTGUARD_HEARTBEAT_INTERVAL_MS || 20000))
};
if (!config.companyId || !config.credential) throw new Error('AGENTGUARD_COMPANY_ID and AGENTGUARD_GATEWAY_CREDENTIAL are required');

const headers = { authorization: `Bearer ${config.credential}`, 'x-agentguard-company': config.companyId };
let agents = new Map();

async function loadConfiguration() {
  const response = await fetch(`${config.controlPlane}/api/gateway/config`, { headers, signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error(`Configuration rejected (${response.status}): ${await response.text()}`);
  const payload = await response.json();
  const next = new Map(payload.agents.map(agent => [agent.agentId, agent]));
  const added = [...next.keys()].filter(id => !agents.has(id));
  const removed = [...agents.keys()].filter(id => !next.has(id));
  agents = next;
  if (added.length || removed.length) console.log(`${new Date().toISOString()} configuration updated: ${agents.size} agents (+${added.length}/-${removed.length})`);
}

async function inspect(agent) {
  const started = Date.now();
  try {
    const response = await fetch(agent.target, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const type = response.headers.get('content-type') || '';
    const health = type.includes('json') ? await response.json() : { reachable: true };
    return { message: `${agent.name} heartbeat`, metrics: { latencyMs: Date.now() - started }, metadata: { health, target: agent.target, adapter: 'company-gateway' } };
  } catch (error) {
    return { status: 'failed', message: `${agent.name} health check failed`, error: error.message, metrics: { latencyMs: Date.now() - started }, metadata: { target: agent.target, adapter: 'company-gateway' } };
  }
}

async function report(agent) {
  const telemetry = await inspect(agent);
  const response = await fetch(`${config.controlPlane}/api/gateway/events`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json', 'x-agentguard-agent': agent.agentId }, body: JSON.stringify({ companyId: config.companyId, agentId: agent.agentId, eventType: 'heartbeat', timestamp: new Date().toISOString(), ...telemetry }) });
  if (!response.ok) throw new Error(`Heartbeat rejected for ${agent.agentId} (${response.status}): ${await response.text()}`);
}

async function reportAll() { await Promise.allSettled([...agents.values()].map(agent => report(agent))); }
await loadConfiguration();
await reportAll();
setInterval(() => loadConfiguration().catch(error => console.error(`${new Date().toISOString()} ${error.message}`)), config.pollMs);
setInterval(() => reportAll().catch(error => console.error(`${new Date().toISOString()} ${error.message}`)), config.heartbeatMs);
console.log(`AgentGuard company gateway running for ${config.companyId}`);
