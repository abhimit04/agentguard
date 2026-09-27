import http from 'node:http';
import { adapters, convertOtlpTraces } from './adapters.mjs';

const port = Number(process.env.CONNECTOR_PORT || 3200);
const controlPlane = (process.env.AGENTGUARD_URL || 'http://host.docker.internal:3100').replace(/\/$/, '');
const connectorKey = process.env.CONNECTOR_KEY || '';
const agentGuardKey = process.env.AGENTGUARD_API_KEY || '';

function json(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(value));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; if (raw.length > 1_000_000) req.destroy(); });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') return json(res, 200, { ok: true, connector: 'agentguard' });
  if (req.method === 'GET' && req.url === '/capabilities') return json(res, 200, { adapters });
  if (req.method !== 'POST' || !['/events', '/v1/traces'].includes(req.url)) return json(res, 404, { error: 'Not found' });
  if (!connectorKey) return json(res, 503, { error: 'Connector key is not configured' });
  if (req.headers.authorization !== `Bearer ${connectorKey}`) return json(res, 401, { error: 'Connector authentication required' });
  try {
    const input = await readBody(req);
    let events;
    if (req.url === '/events') {
      if (!input.agentId || !(input.eventType || input.event)) return json(res, 400, { error: 'agentId and eventType are required' });
      events = [input];
    } else {
      const inventoryResponse = await fetch(`${controlPlane}/api/agents`, { headers: agentGuardKey ? { authorization: `Bearer ${agentGuardKey}` } : {} });
      if (!inventoryResponse.ok) return json(res, inventoryResponse.status, { error: 'Could not read AgentGuard agent inventory' });
      events = convertOtlpTraces(input, await inventoryResponse.json());
      if (!events.length) return json(res, 200, { accepted: 0 });
      if (events.length > 500) return json(res, 413, { error: 'OTLP batch exceeds 500 spans' });
    }
    for (const event of events) {
      const normalized = { companyId: event.companyId || 'default', agentId: event.agentId, eventType: event.eventType || event.event, status: event.status === 'error' ? 'failed' : undefined, message: event.message, timestamp: event.timestamp, task: event.taskId ? { id: event.taskId, name: event.message } : undefined, error: event.status === 'error' ? event.message : undefined, traceId: event.traceId || event.runId, spanId: event.spanId || event.taskId, tool: event.tool, metrics: event.metrics || { latencyMs: event.durationMs }, metadata: event.metadata };
      const response = await fetch(`${controlPlane}/api/gateway/events`, { method: 'POST', headers: { 'content-type': 'application/json', ...(agentGuardKey ? { authorization: `Bearer ${agentGuardKey}` } : {}) }, body: JSON.stringify(normalized) });
      if (!response.ok) return json(res, response.status, await response.json().catch(() => ({ error: 'AgentGuard rejected event' })));
    }
    return json(res, 200, { ok: true, accepted: events.length });
  } catch (error) { return json(res, 502, { error: error.message }); }
});

server.listen(port, () => console.log(`AgentGuard connector listening on http://localhost:${port}`));
