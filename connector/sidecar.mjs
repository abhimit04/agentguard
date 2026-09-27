const settings = {
  gateway: (process.env.AGENTGUARD_URL || 'http://localhost:3100').replace(/\/$/, ''),
  companyId: process.env.AGENTGUARD_COMPANY_ID || 'default',
  agentId: process.env.AGENTGUARD_AGENT_ID || '',
  credential: process.env.AGENTGUARD_CREDENTIAL || '',
  target: process.env.AGENTGUARD_TARGET_URL || process.argv.find(value => value.startsWith('http')) || '',
  intervalMs: Math.max(5000, Number(process.env.AGENTGUARD_HEARTBEAT_INTERVAL_MS || 20000))
};

function validate() {
  for (const [key, value] of Object.entries(settings)) if (key !== 'intervalMs' && !value) throw new Error(`Missing ${key}. Configure the AgentGuard sidecar environment.`);
}

async function targetHealth() {
  const started = Date.now();
  const response = await fetch(settings.target, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error(`Target returned HTTP ${response.status}`);
  const contentType = response.headers.get('content-type') || '';
  const snapshot = contentType.includes('json') ? await response.json() : { reachable: true };
  return { snapshot, latencyMs: Date.now() - started };
}

async function heartbeat() {
  let status = 'waiting', error = null, health = null, latencyMs = null;
  try { const result = await targetHealth(); health = result.snapshot; latencyMs = result.latencyMs; }
  catch (cause) { status = 'failed'; error = cause.message; }
  const response = await fetch(`${settings.gateway}/api/gateway/agents/${encodeURIComponent(settings.agentId)}/heartbeat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${settings.credential}`, 'x-agentguard-company': settings.companyId, 'x-agentguard-agent': settings.agentId },
    body: JSON.stringify({ status, message: error ? `Sidecar health check failed: ${error}` : 'Sidecar heartbeat', error, metrics: { latencyMs }, metadata: { target: settings.target, health, adapter: 'agentguard-sidecar' } })
  });
  if (!response.ok) throw new Error(`AgentGuard rejected heartbeat (${response.status}): ${await response.text()}`);
  console.log(`${new Date().toISOString()} heartbeat accepted for ${settings.companyId}/${settings.agentId} (${status})`);
}

validate();
await heartbeat();
const timer = setInterval(() => heartbeat().catch(error => console.error(`${new Date().toISOString()} ${error.message}`)), settings.intervalMs);
process.on('SIGINT', () => { clearInterval(timer); process.exit(0); });
process.on('SIGTERM', () => { clearInterval(timer); process.exit(0); });
