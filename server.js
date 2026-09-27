const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
if (fs.existsSync(path.join(__dirname, '.env'))) {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}
const { readStore, writeStore, initializeStore } = require('./storage');
const { issueToken, tokenMatches, normalizeEnvelope, applyEnvelope, expireHeartbeats, expireRuntimeActivity } = require('./gateway');
const auth = require('./auth');
const { roleFor, can } = require('./rbac');

const port = Number(process.env.PORT || 3100);
const dist = path.join(__dirname, 'dist');
const seed = { schemaVersion: 8, companies: [{ id: 'default', name: 'Default workspace' }], agents: [], policies: [], approvals: [], assessments: [], events: [] };
const integrationApiKey = process.env.AGENTGUARD_API_KEY || '';
const requireAuth = process.env.AGENTGUARD_REQUIRE_AUTH === 'true';
const rateWindow = new Map();
const managedPollMs = Math.max(5000, Number(process.env.AGENTGUARD_CONNECTOR_POLL_MS || 15000));
function json(res, code, body) { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(JSON.stringify(body)); }
function redirect(res, location, headers = {}) { res.writeHead(302, { Location: location, ...headers }); res.end(); }
function secureHeaders(res) { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer'); }
function authorizedIntegration(req) { return !integrationApiKey || req.headers.authorization === `Bearer ${integrationApiKey}` || req.headers['x-agentguard-api-key'] === integrationApiKey; }
function gatewayIdentity(req, store, requestedAgentId) {
  const companyId = String(req.headers['x-agentguard-company'] || '');
  const agentId = String(req.headers['x-agentguard-agent'] || requestedAgentId || '');
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const agent = store.agents.find(item => item.id === agentId && item.companyId === companyId);
  return agent && tokenMatches(token, agent.credentialHash) ? agent : null;
}
function limited(req) { const key = req.socket.remoteAddress || 'local'; const now = Date.now(); const recent = (rateWindow.get(key) || []).filter(time => now - time < 60_000); recent.push(now); rateWindow.set(key, recent); return recent.length > Number(process.env.AGENTGUARD_RATE_LIMIT || 240); }
function event(store, kind, message, metadata = {}) {
  store.events.unshift({
    ...metadata,
    id: randomUUID(),
    kind,
    message,
    createdAt: new Date().toISOString(),
    actor: metadata.actor || metadata.decidedBy || (metadata.agentId ? `agent:${metadata.agentId}` : 'system')
  });
}
function publicAgents(agents) { return agents.map(({ credentialHash, ...agent }) => agent); }
function publicCompanies(companies) { return companies.map(({ gatewayCredentialHash, ...company }) => company); }
function generateAgentId(store) {
  const used = new Set(store.agents.map(agent => String(agent.id)));
  if (used.size >= 9000) throw new Error('Four-digit agent ID capacity has been reached');
  let id;
  do { id = String(Math.floor(1000 + Math.random() * 9000)); } while (used.has(id));
  return id;
}
function companyGateway(req, store) {
  const companyId = String(req.headers['x-agentguard-company'] || '');
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const company = store.companies.find(item => item.id === companyId);
  return company && tokenMatches(token, company.gatewayCredentialHash) ? company : null;
}
function matchesPattern(pattern, value) {
  if (!pattern || pattern === '*') return true;
  const expected = String(pattern).toLowerCase();
  const actual = String(value || '').toLowerCase();
  return expected.endsWith('*') ? actual.startsWith(expected.slice(0, -1)) : actual === expected;
}
function body(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; if (raw.length > 100000) req.destroy(); });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid JSON')); } });
  });
}

function normalizedRuntimeUrl(value) {
  const url = new URL(String(value || '').trim());
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Runtime URL must use http or https');
  if (url.username || url.password) throw new Error('Put credentials in the connector header, not in the URL');
  if (url.hostname === '169.254.169.254') throw new Error('Cloud metadata addresses are not allowed');
  return url.toString().replace(/\/$/, '');
}

function runtimeUrlOwner(store, runtimeUrl, exceptAgentId) {
  const normalized = normalizedRuntimeUrl(runtimeUrl);
  return store.agents.find(item => item.id !== exceptAgentId && !item.archived && item.connection?.desiredState === 'running' && item.connection?.runtimeUrl === normalized) || null;
}

async function probeManagedAgent(agent) {
  const connection = agent.connection || {};
  if (!connection.runtimeUrl) throw new Error('Add the agent runtime URL before starting');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const headers = { accept: 'application/json' };
    if (connection.authHeader) headers.authorization = connection.authHeader;
    const response = await fetch(connection.runtimeUrl, { method: 'GET', headers, signal: controller.signal });
    if (!response.ok) throw new Error(`Agent API returned HTTP ${response.status}`);
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('json')) throw new Error('Agent API must return JSON');
    const snapshot = await response.json();
    if (!snapshot || typeof snapshot !== 'object') throw new Error('Agent API returned an invalid JSON response');
    if (snapshot.ok === false) throw new Error(snapshot.error || 'Agent API reported an error');
    return snapshot;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Runtime did not respond within 5 seconds');
    throw error;
  } finally { clearTimeout(timeout); }
}

async function refreshManagedConnection(agentId, recordEvent = false) {
  const before = readStore();
  const current = before.agents.find(item => item.id === agentId);
  if (!current || current.archived || current.connection?.desiredState !== 'running') return null;
  try {
    const duplicateBindings = before.agents.filter(item => !item.archived && item.connection?.desiredState === 'running' && item.connection?.runtimeUrl === current.connection.runtimeUrl);
    if (duplicateBindings[0]?.id !== current.id) throw new Error(`API URL is already bound to ${duplicateBindings[0].name} (${duplicateBindings[0].id})`);
    const snapshot = await probeManagedAgent(current);
    const store = readStore();
    const agent = store.agents.find(item => item.id === agentId);
    if (!agent || agent.connection?.desiredState !== 'running') return null;
    const wasConnected = agent.status === 'healthy';
    const previousSnapshot = agent.telemetrySnapshot;
    const snapshotChanged = JSON.stringify(previousSnapshot || null) !== JSON.stringify(snapshot);
    agent.status = 'healthy';
    agent.lastSeenAt = new Date().toISOString();
    agent.telemetrySnapshot = snapshot;
    agent.connection = { ...agent.connection, state: 'connected', lastError: null, lastCheckedAt: agent.lastSeenAt };
    if (recordEvent || !wasConnected) event(store, 'action', `Managed connector started: ${agent.name}`, { agentId, eventType: 'connector.connected', metadata: snapshot, actor: 'connector:managed-http' });
    if (wasConnected && snapshotChanged) {
      const status = snapshot.status || snapshot.runtimeStatus || 'activity update';
      const message = snapshot.message || snapshot.currentTask || `${agent.name} reported ${status}`;
      event(store, 'action', message, { agentId, eventType: 'agent.activity', status, currentTask: snapshot.currentTask || null, metadata: snapshot, actor: `agent:${agent.id}` });
    }
    writeStore(store);
    return agent;
  } catch (error) {
    const store = readStore();
    const agent = store.agents.find(item => item.id === agentId);
    if (!agent) return null;
    const wasConnected = agent.status === 'healthy';
    agent.status = 'registered';
    agent.connection = { ...agent.connection, state: 'error', lastError: error.message, lastCheckedAt: new Date().toISOString() };
    if (wasConnected || recordEvent) event(store, 'block', `Connector check failed for ${agent.name}: ${error.message}`, { agentId, eventType: 'connector.failed', actor: 'connector:managed-http' });
    writeStore(store);
    throw error;
  }
}

const server = http.createServer(async (req, res) => {
  secureHeaders(res);
  const url = new URL(req.url, 'http://localhost');
  const requireRole = permission => {
    if (!requireAuth) return true;
    const user = auth.session(req);
    if (!user) { json(res, 401, { error: 'Authentication required', login: '/auth/login' }); return false; }
    if (!can(user, permission)) { json(res, 403, { error: `Role ${roleFor(user)} cannot perform this action` }); return false; }
    return true;
  };
  if (url.pathname === '/auth/login' && req.method === 'GET') return auth.login(res);
  if (url.pathname === '/auth/callback' && req.method === 'GET') { try { return await auth.callback(req, res, url.searchParams.get('code'), url.searchParams.get('state')); } catch (error) { console.error('Google auth callback failed:', error.message, error.cause?.message || ''); return json(res, 500, { error: 'Authentication failed', detail: process.env.NODE_ENV === 'production' ? undefined : error.message }); } }
  if (url.pathname === '/auth/logout' && req.method === 'GET') return auth.logout(req, res);
  if (url.pathname === '/api/session' && req.method === 'GET') { const user = auth.session(req); return json(res, 200, { authenticated: Boolean(user), user, role: roleFor(user) }); }
  if (url.pathname === '/api/companies' && req.method === 'GET') {
    if (requireAuth && !auth.session(req)) return json(res, 401, { error: 'Authentication required', login: '/auth/login' });
    return json(res, 200, publicCompanies(readStore().companies));
  }
  if (url.pathname === '/api/companies' && req.method === 'POST') {
    if (!requireRole('configure')) return;
    try {
      const input = await body(req); const name = String(input.name || '').trim();
      const requestedId = String(input.id || '').trim().toLowerCase();
      const baseId = requestedId || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
      if (!name || !baseId || !/^[a-z0-9][a-z0-9._-]{1,63}$/.test(baseId)) return json(res, 400, { error: 'Valid company name is required' });
      const store = readStore(); let id = baseId; let suffix = 2;
      while (store.companies.some(company => company.id === id)) id = `${baseId.slice(0, 63 - String(suffix).length - 1)}-${suffix++}`;
      const credential = issueToken(); const company = { id, name, gatewayCredentialHash: credential.hash, createdAt: new Date().toISOString() };
      store.companies.push(company); event(store, 'action', `Company registered: ${name}`, { companyId: id, actor: 'workspace-user' }); writeStore(store);
      return json(res, 201, { id, name, gatewayCredential: credential.token });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  const companyCredentialMatch = url.pathname.match(/^\/api\/companies\/([^/]+)\/gateway-credentials$/);
  if (companyCredentialMatch && req.method === 'POST') {
    if (!requireRole('configure')) return;
    const store = readStore(); const company = store.companies.find(item => item.id === decodeURIComponent(companyCredentialMatch[1]));
    if (!company) return json(res, 404, { error: 'Company not found' });
    const credential = issueToken(); company.gatewayCredentialHash = credential.hash;
    event(store, 'action', `Company gateway credential rotated: ${company.name}`, { companyId: company.id, actor: 'workspace-user' }); writeStore(store);
    return json(res, 201, { companyId: company.id, gatewayCredential: credential.token });
  }
  if (url.pathname === '/api/gateway/config' && req.method === 'GET') {
    const store = readStore(); const company = companyGateway(req, store);
    if (!company) return json(res, 401, { error: 'Invalid company gateway credential' });
    const agents = store.agents.filter(agent => agent.companyId === company.id && !agent.archived && agent.connection?.desiredState === 'running' && agent.connection?.runtimeUrl).map(agent => ({ agentId: agent.id, name: agent.name, target: agent.connection.runtimeUrl, framework: agent.framework || 'unknown', version: agent.version || null }));
    return json(res, 200, { version: String(store.schemaVersion), companyId: company.id, refreshAfterMs: 10000, agents });
  }
  if (url.pathname === '/api/gateway/contract' && req.method === 'GET') return json(res, 200, { version: '1.0', endpoint: '/api/gateway/events', required: ['companyId', 'agentId', 'eventType'], statuses: ['running', 'waiting', 'failed', 'offline'], authentication: 'Bearer agent credential', telemetry: ['heartbeat', 'task', 'error', 'latency', 'tokens', 'logs', 'traces'] });
  if (url.pathname === '/api/gateway/companies/register' && req.method === 'POST') {
    if (!authorizedIntegration(req)) return json(res, 401, { error: 'Platform onboarding credential required' });
    try {
      const input = await body(req); const companyId = String(input.companyId || input.company_id || '').trim().toLowerCase(); const name = String(input.companyName || input.company_name || input.name || '').trim();
      if (!companyId || !name || !/^[a-z0-9][a-z0-9._-]{1,63}$/.test(companyId)) return json(res, 400, { error: 'Valid companyId and companyName are required' });
      const store = readStore(); let company = store.companies.find(item => item.id === companyId); const credential = issueToken();
      if (company) { company.name = name; company.gatewayCredentialHash = credential.hash; }
      else { company = { id: companyId, name, gatewayCredentialHash: credential.hash, createdAt: new Date().toISOString() }; store.companies.push(company); }
      event(store, 'action', `Company gateway provisioned: ${name}`, { companyId, actor: 'gateway:registry' }); writeStore(store);
      return json(res, 201, { companyId, companyName: name, gatewayCredential: credential.token, configEndpoint: '/api/gateway/config' });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/gateway/agents/register' && req.method === 'POST') {
    if (!authorizedIntegration(req)) return json(res, 401, { error: 'Company onboarding credential required' });
    try {
      const input = await body(req);
      const companyId = String(input.companyId || input.company_id || '').trim();
      const name = String(input.agentName || input.agent_name || input.name || '').trim();
      if (!companyId || !name) return json(res, 400, { error: 'companyId and agentName are required' });
      const store = readStore();
      const agentId = generateAgentId(store);
      if (!store.companies.some(company => company.id === companyId)) store.companies.push({ id: companyId, name: input.companyName || input.company_name || companyId, createdAt: new Date().toISOString() });
      if (store.agents.some(agent => agent.id === agentId && agent.companyId === companyId)) return json(res, 409, { error: 'Agent is already registered for this company' });
      const credential = issueToken();
      const runtimeUrl = input.runtimeUrl || input.runtime_url || null;
      const agent = { id: agentId, companyId, name, agentType: input.agentType || input.agent_type || 'general', framework: input.framework || 'unknown', model: input.model || null, version: input.version || null, team: input.team || 'Unassigned', tools: Array.isArray(input.tools) ? input.tools : [], parentId: input.parentId || input.parent_id || null, riskTier: input.riskTier || 'unassessed', dataClass: input.dataClass || 'internal', autonomy: input.autonomy || 'assistive', status: 'registered', runtimeStatus: 'offline', createdAt: new Date().toISOString(), lastSeenAt: null, credentialHash: credential.hash, connection: { mode: 'gateway', runtimeUrl: runtimeUrl ? normalizedRuntimeUrl(runtimeUrl) : null, desiredState: 'running', state: 'awaiting_telemetry' } };
      store.agents.push(agent); event(store, 'action', `Agent registered through gateway: ${agent.name}`, { agentId, companyId, actor: 'gateway:registry' }); writeStore(store);
      return json(res, 201, { companyId, agentId, gatewayCredential: credential.token, endpoints: { status: `/api/gateway/agents/${encodeURIComponent(agentId)}/status`, heartbeat: `/api/gateway/agents/${encodeURIComponent(agentId)}/heartbeat`, events: `/api/gateway/agents/${encodeURIComponent(agentId)}/events`, health: `/api/gateway/agents/${encodeURIComponent(agentId)}/health`, otlp: 'http://localhost:4318' } });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  const gatewayAgentMatch = url.pathname.match(/^\/api\/gateway\/agents\/([^/]+)\/(status|heartbeat|events|health)$/);
  if (gatewayAgentMatch) {
    const agentId = decodeURIComponent(gatewayAgentMatch[1]);
    const operation = gatewayAgentMatch[2];
    const store = readStore();
    const agent = gatewayIdentity(req, store, agentId);
    if (!agent) return json(res, 401, { error: 'Invalid company or agent credential' });
    if ((operation === 'status' || operation === 'health') && req.method === 'GET') return json(res, 200, { companyId: agent.companyId, agentId: agent.id, status: agent.runtimeStatus || 'offline', health: agent.status === 'healthy' ? 'healthy' : 'offline', currentTask: agent.currentTask || null, lastHeartbeat: agent.lastSeenAt, version: agent.version || null, usage: agent.usage || null });
    if ((operation === 'heartbeat' || operation === 'events') && req.method === 'POST') {
      try {
        const input = await body(req);
        const envelope = normalizeEnvelope({ ...input, companyId: agent.companyId, agentId: agent.id, eventType: operation === 'heartbeat' ? 'heartbeat' : input.eventType || input.event });
        const result = applyEnvelope(store, envelope, event); writeStore(store);
        return json(res, 202, { accepted: result.duplicate ? 0 : 1, duplicate: result.duplicate, status: result.agent.runtimeStatus });
      } catch (error) { return json(res, error.statusCode || 400, { error: error.message }); }
    }
    return json(res, 405, { error: 'Method not allowed' });
  }
  if (url.pathname === '/api/gateway/events' && req.method === 'POST') {
    if (limited(req)) return json(res, 429, { error: 'Rate limit exceeded' });
    try {
      const input = await body(req);
      const envelopes = (Array.isArray(input) ? input : [input]).map(normalizeEnvelope);
      if (!envelopes.length || envelopes.length > 500) return json(res, 400, { error: 'Send between 1 and 500 telemetry events' });
      const companyId = req.headers['x-agentguard-company'] || envelopes[0].companyId;
      const agentId = req.headers['x-agentguard-agent'] || envelopes[0].agentId;
      if (envelopes.some(item => item.companyId !== companyId || item.agentId !== agentId)) return json(res, 400, { error: 'A gateway batch must contain one company and one agent identity' });
      const store = readStore();
      const agent = store.agents.find(item => item.id === agentId && item.companyId === companyId);
      const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const trustedGateway = Boolean(integrationApiKey) && authorizedIntegration(req);
      const company = store.companies.find(item => item.id === companyId);
      const trustedCompany = company && tokenMatches(token, company.gatewayCredentialHash);
      if (!agent || (!trustedGateway && !trustedCompany && !tokenMatches(token, agent.credentialHash))) return json(res, 401, { error: 'Invalid company, gateway, or agent credential' });
      let accepted = 0, duplicates = 0;
      for (const envelope of envelopes) { const result = applyEnvelope(store, envelope, event); result.duplicate ? duplicates++ : accepted++; }
      writeStore(store);
      return json(res, 202, { accepted, duplicates, agentId, companyId });
    } catch (error) { return json(res, error.statusCode || 400, { error: error.message }); }
  }
  const integrationRoute = ['/api/agent-events', '/api/v1/events', '/api/guard/check'].includes(url.pathname);
  if (integrationRoute && limited(req)) return json(res, 429, { error: 'Rate limit exceeded' });
  if (integrationRoute && !authorizedIntegration(req)) return json(res, 401, { error: 'AgentGuard integration API key required' });
  if (url.pathname === '/api/health') return json(res, 200, { ok: true });
  if (url.pathname === '/api/dashboard' && req.method === 'GET') {
    if (requireAuth && !auth.session(req)) return json(res, 401, { error: 'Authentication required', login: '/auth/login' });
    const store = readStore();
    return json(res, 200, { ...store, companies: publicCompanies(store.companies), agents: publicAgents(store.agents), approvals: store.approvals.filter(approval => approval.status === 'pending'), events: store.events.filter(item => item.eventType !== 'heartbeat' && !/\bheartbeat\b|agent is online/i.test(item.message || '')) });
  }
  const assessmentMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/assessment$/);
  if (assessmentMatch && req.method === 'GET') {
    if (requireAuth && !auth.session(req)) return json(res, 401, { error: 'Authentication required', login: '/auth/login' });
    const store = readStore(); const assessment = store.assessments.find(item => item.agentId === decodeURIComponent(assessmentMatch[1]));
    return json(res, 200, assessment || null);
  }
  if (assessmentMatch && (req.method === 'POST' || req.method === 'PATCH')) {
    if (!requireRole('configure')) return;
    try {
      const store = readStore(); const agentId = decodeURIComponent(assessmentMatch[1]);
      if (!store.agents.some(agent => agent.id === agentId)) return json(res, 404, { error: 'Agent not found' });
      const input = await body(req); const now = new Date().toISOString();
      const fields = ['purpose', 'intendedUse', 'prohibitedUse', 'dataTypes', 'affectedPeople', 'impactLevel', 'privacyRisk', 'biasRisk', 'securityRisk', 'humanOversight', 'mitigations', 'owner', 'reviewDueAt', 'status'];
      let assessment = store.assessments.find(item => item.agentId === agentId);
      if (!assessment) { assessment = { id: randomUUID(), agentId, createdAt: now }; store.assessments.push(assessment); }
      for (const field of fields) if (input[field] !== undefined) assessment[field] = input[field];
      assessment.updatedAt = now; assessment.status = assessment.status || 'draft';
      event(store, 'action', `AI risk assessment ${req.method === 'POST' ? 'created' : 'updated'} for ${agentId}`, { agentId, eventType: 'assessment.updated', metadata: { status: assessment.status, impactLevel: assessment.impactLevel || null } });
      writeStore(store); return json(res, req.method === 'POST' ? 201 : 200, assessment);
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/agents' && req.method === 'GET') {
    if (integrationApiKey && authorizedIntegration(req)) return json(res, 200, publicAgents(readStore().agents));
    if (requireAuth && !auth.session(req)) return json(res, 401, { error: 'Authentication required', login: '/auth/login' });
    return json(res, 200, publicAgents(readStore().agents));
  }
  if (url.pathname === '/api/agents' && req.method === 'POST') {
    if (!requireRole('operate')) return;
    try {
      const input = await body(req);
      if (!input.name || !input.team || !Array.isArray(input.tools)) return json(res, 400, { error: 'name, team, and tools are required' });
      const store = readStore();
      const companyId = String(input.companyId || '').trim().toLowerCase();
      if (!companyId) return json(res, 400, { error: 'Select or create a company before registering an agent' });
      if (!store.companies.some(company => company.id === companyId)) return json(res, 404, { error: 'Unknown company' });
      if (input.parentId && !store.agents.some(parent => parent.id === input.parentId && parent.companyId === companyId)) return json(res, 400, { error: 'Parent agent must belong to the same company' });
      const credential = issueToken();
      const agent = { id: generateAgentId(store), companyId, name: input.name, agentType: input.agentType || 'general', framework: input.framework || 'unknown', model: input.model || null, version: input.version || null, team: input.team, tools: input.tools, parentId: input.parentId || null, riskTier: input.riskTier || 'unassessed', dataClass: input.dataClass || 'internal', autonomy: input.autonomy || 'assistive', status: 'registered', runtimeStatus: 'offline', createdAt: new Date().toISOString(), lastSeenAt: null, credentialHash: credential.hash, connection: input.runtimeUrl ? { mode: 'url-binding', runtimeUrl: normalizedRuntimeUrl(input.runtimeUrl), desiredState: 'stopped', state: 'stopped' } : { mode: 'gateway', desiredState: 'running', state: 'awaiting_telemetry' } };
      store.agents.push(agent); event(store, 'action', `Agent registered: ${agent.name}`, { agentId: agent.id, actor: 'workspace-user' }); writeStore(store);
      return json(res, 201, { ...agent, credentialHash: undefined, gatewayCredential: credential.token, gateway: { endpoint: '/api/gateway/events', companyId, agentId: agent.id, modes: ['opentelemetry', 'sidecar', 'gateway', 'sdk'] } });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/agents/bulk' && req.method === 'POST') {
    if (!((integrationApiKey && authorizedIntegration(req)) || requireRole('operate'))) return;
    try {
      const input = await body(req);
      if (!Array.isArray(input.agents) || !input.agents.length) return json(res, 400, { error: 'agents must be a non-empty array' });
      if (input.agents.length > 1000) return json(res, 400, { error: 'Maximum 1000 agents per request' });
      const store = readStore(); const created = []; const rejected = []; const companyId = String(input.companyId || 'default');
      if (!store.companies.some(company => company.id === companyId)) return json(res, 404, { error: 'Unknown company' });
      for (const item of input.agents) {
        const name = String(item.name || '').trim();
        if (!name) { rejected.push({ item, reason: 'name is required' }); continue; }
        const id = generateAgentId(store);
        const agent = { id, companyId, name, team: item.team || input.team || 'Unassigned', tools: Array.isArray(item.tools) ? item.tools : [], parentId: item.parentId || null, riskTier: item.riskTier || input.riskTier || 'unassessed', dataClass: item.dataClass || input.dataClass || 'internal', autonomy: item.autonomy || input.autonomy || 'assistive', status: 'registered', runtimeStatus: 'offline', createdAt: new Date().toISOString(), lastSeenAt: null };
        store.agents.push(agent); created.push(agent); event(store, 'action', `Agent registered: ${agent.name}`, { agentId: agent.id, actor: 'workspace-user' });
      }
      writeStore(store); return json(res, 201, { created, rejected, count: created.length });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  const agentMatch = url.pathname.match(/^\/api\/agents\/([^/]+)$/);
  if (agentMatch && req.method === 'PATCH') {
    if (!requireRole('configure')) return;
    try {
      const store = readStore();
      const agent = store.agents.find(item => item.id === agentMatch[1]);
      if (!agent) return json(res, 404, { error: 'Agent not found' });
      const input = await body(req);
      if (input.archived !== undefined) { if (typeof input.archived !== 'boolean') return json(res, 400, { error: 'archived must be boolean' }); agent.archived = input.archived; agent.status = input.archived ? 'archived' : 'registered'; }
      if (input.companyId !== undefined) {
        const companyId = String(input.companyId);
        if (!store.companies.some(company => company.id === companyId)) return json(res, 404, { error: 'Unknown company' });
        agent.companyId = companyId;
      }
      for (const field of ['name', 'team', 'parentId', 'riskTier', 'dataClass', 'autonomy']) if (input[field] !== undefined) agent[field] = input[field];
      if (agent.parentId) {
        const parent = store.agents.find(item => item.id === agent.parentId);
        if (!parent || parent.companyId !== agent.companyId) return json(res, 400, { error: 'Parent agent must belong to the same company' });
      }
      if (input.runtimeUrl !== undefined) agent.connection = input.runtimeUrl ? { ...(agent.connection || {}), mode: 'managed-http', runtimeUrl: normalizedRuntimeUrl(input.runtimeUrl), desiredState: 'stopped', state: 'stopped', lastError: null } : null;
      if (input.tools !== undefined) { if (!Array.isArray(input.tools)) return json(res, 400, { error: 'tools must be an array' }); agent.tools = input.tools; }
      event(store, 'action', input.archived === undefined ? `Agent updated: ${agent.name}` : `Agent ${input.archived ? 'archived' : 'restored'}: ${agent.name}`, { agentId: agent.id, actor: 'workspace-user' });
      writeStore(store);
      return json(res, 200, agent);
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  const credentialMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/credentials$/);
  if (credentialMatch && req.method === 'POST') {
    if (!requireRole('configure')) return;
    const store = readStore();
    const agent = store.agents.find(item => item.id === decodeURIComponent(credentialMatch[1]));
    if (!agent) return json(res, 404, { error: 'Agent not found' });
    const credential = issueToken();
    agent.credentialHash = credential.hash;
    agent.connection = { ...(agent.connection || {}), mode: 'gateway', desiredState: 'running', state: 'awaiting_telemetry', lastError: null };
    agent.status = 'registered'; agent.runtimeStatus = 'offline';
    event(store, 'action', `Gateway credential rotated: ${agent.name}`, { agentId: agent.id, companyId: agent.companyId, actor: 'workspace-user' });
    writeStore(store);
    return json(res, 201, { companyId: agent.companyId, agentId: agent.id, gatewayCredential: credential.token, endpoint: '/api/gateway/events' });
  }
  const connectionMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/connection\/(start|stop)$/);
  if (connectionMatch && req.method === 'POST') {
    if (!requireRole('operate')) return;
    const agentId = decodeURIComponent(connectionMatch[1]);
    const action = connectionMatch[2];
    const store = readStore();
    const agent = store.agents.find(item => item.id === agentId);
    if (!agent) return json(res, 404, { error: 'Agent not found' });
    if (agent.archived) return json(res, 409, { error: 'Restore this agent before connecting it' });
    if (action === 'stop') {
      agent.status = 'registered';
      agent.connection = { ...(agent.connection || {}), desiredState: 'stopped', state: 'stopped', lastError: null };
      event(store, 'action', `Managed connector stopped: ${agent.name}`, { agentId, eventType: 'connector.stopped', actor: 'workspace-user' });
      writeStore(store);
      return json(res, 200, agent);
    }
    try {
      const input = await body(req);
      const runtimeUrl = input.runtimeUrl || agent.connection?.runtimeUrl;
      const normalizedUrl = normalizedRuntimeUrl(runtimeUrl);
      const owner = runtimeUrlOwner(store, normalizedUrl, agent.id);
      if (owner) return json(res, 409, { error: `This API URL is already connected to ${owner.name} (${owner.id}). Use that agent's Stop action before rebinding it.` });
      agent.connection = { ...(agent.connection || {}), mode: 'url-binding', runtimeUrl: normalizedUrl, boundAgentId: agent.id, desiredState: 'running', state: 'connecting', lastError: null };
      writeStore(store);
      return json(res, 200, await refreshManagedConnection(agentId, true));
    } catch (error) { return json(res, 502, { error: error.message }); }
  }
  if (url.pathname === '/api/policies' && req.method === 'POST') {
    if (!requireRole('configure')) return;
    try {
      const input = await body(req);
      if (!input.name || !input.scope || !input.agentId || !input.actionType) return json(res, 400, { error: 'name, scope, agentId, and actionType are required' });
      if (!['allow', 'require_approval', 'block'].includes(input.effect || 'require_approval')) return json(res, 400, { error: 'effect must be allow, require_approval, or block' });
      if (!Number.isInteger(Number(input.priority ?? 100))) return json(res, 400, { error: 'priority must be an integer' });
      const store = readStore();
      if (input.agentId !== '*' && !store.agents.some(agent => agent.id === input.agentId)) return json(res, 404, { error: 'Unknown agent' });
      const now = new Date().toISOString();
      const policy = { id: randomUUID(), name: input.name, scope: input.scope, agentId: input.agentId, actionType: input.actionType, resourcePattern: input.resourcePattern || '*', effect: input.effect || 'require_approval', priority: Number(input.priority ?? 100), enabled: Boolean(input.enabled), version: 1, createdAt: now, updatedAt: now };
      store.policies.push(policy); event(store, 'action', `Policy created: ${policy.name}`, { policyId: policy.id, version: policy.version, actor: 'workspace-user' }); writeStore(store);
      return json(res, 201, policy);
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/guard/check' && req.method === 'POST') {
    try {
      const input = await body(req);
      if (!input.agentId || !input.actionType || !input.action || !input.actionRef) return json(res, 400, { error: 'agentId, actionType, action, and actionRef are required' });
      const store = readStore();
      const agent = store.agents.find(x => x.id === input.agentId);
      if (!agent) {
        if (!input.agent || !input.agent.name || !input.agent.team || !Array.isArray(input.agent.tools)) return json(res, 404, { error: 'Unknown agent' });
        store.agents.push({ ...input.agent, id: input.agentId, status: 'healthy', createdAt: new Date().toISOString(), lastSeenAt: new Date().toISOString() });
      }
      const connectedAgent = store.agents.find(x => x.id === input.agentId);
      if (connectedAgent.archived) return json(res, 409, { error: 'Agent is archived; restore it before sending activity' });
      connectedAgent.status = 'healthy';
      connectedAgent.lastSeenAt = new Date().toISOString();
      connectedAgent.lastActivityAt = connectedAgent.lastSeenAt;
      connectedAgent.runtimeStatus = 'running';
      connectedAgent.currentTask = { id: input.actionRef || null, name: input.action };
      const resource = input.resource || '*';
      const effectRank = { block: 3, require_approval: 2, allow: 1 };
      const policy = store.policies
        .filter(x => x.enabled && (x.agentId === '*' || x.agentId === input.agentId) && matchesPattern(x.actionType, input.actionType) && matchesPattern(x.resourcePattern, resource))
        .sort((a, b) => (b.priority ?? 100) - (a.priority ?? 100) || (effectRank[b.effect] ?? 0) - (effectRank[a.effect] ?? 0))[0];
      if (!policy) {
        event(store, 'action', `Allowed by default: ${input.action}`, { agentId: input.agentId, actionType: input.actionType, resource, actionRef: input.actionRef });
        writeStore(store);
        return json(res, 200, { decision: 'allow' });
      }
      const existing = store.approvals.find(x => x.actionRef === input.actionRef);
      if (existing?.status === 'approved') return json(res, 200, { decision: 'allow', approvalId: existing.id });
      if (existing?.status === 'denied') return json(res, 200, { decision: 'block', approvalId: existing.id, policy: existing.risk });
      if (policy.effect === 'block') {
        event(store, 'block', `Blocked by ${policy.name}: ${input.action}`, { agentId: input.agentId, actionType: input.actionType, resource, actionRef: input.actionRef, policyId: policy.id });
        writeStore(store);
        return json(res, 200, { decision: 'block', policyId: policy.id, policy: policy.name });
      }
      if (policy.effect === 'allow') {
        event(store, 'action', `Allowed by ${policy.name}: ${input.action}`, { agentId: input.agentId, actionType: input.actionType, resource, actionRef: input.actionRef, policyId: policy.id });
        writeStore(store);
        return json(res, 200, { decision: 'allow', policyId: policy.id });
      }
      const existingPending = store.approvals.find(x => x.actionRef === input.actionRef && x.status === 'pending');
      if (existingPending) return json(res, 200, { decision: 'awaiting_approval', approvalId: existingPending.id });
      const approval = { id: randomUUID(), agentId: input.agentId, action: input.action, resource, risk: policy.name, actionRef: input.actionRef, policyId: policy.id, status: 'pending', createdAt: new Date().toISOString() };
      store.approvals.push(approval);
      event(store, 'approval', `Approval required by ${policy.name}: ${approval.action}`, { agentId: input.agentId, actionType: input.actionType, resource, actionRef: input.actionRef, approvalId: approval.id, policyId: policy.id });
      writeStore(store);
      return json(res, 202, { decision: 'awaiting_approval', approvalId: approval.id });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  const approvalStatusMatch = url.pathname.match(/^\/api\/approvals\/([^/]+)$/);
  if (approvalStatusMatch && req.method === 'GET') {
    const approval = readStore().approvals.find(x => x.id === approvalStatusMatch[1]);
    if (!approval) return json(res, 404, { error: 'Approval not found' });
    return json(res, 200, { id: approval.id, status: approval.status, decision: approval.decision || null });
  }
  if (url.pathname === '/api/approvals' && req.method === 'POST') {
    if (!requireRole('operate')) return;
    try {
      const input = await body(req);
      if (!input.agentId || !input.action || !input.risk) return json(res, 400, { error: 'agentId, action, and risk are required' });
      const store = readStore();
      if (!store.agents.some(agent => agent.id === input.agentId)) return json(res, 404, { error: 'Unknown agent' });
      const approval = { id: randomUUID(), agentId: input.agentId, action: input.action, risk: input.risk, createdAt: new Date().toISOString() };
      approval.status = 'pending';
      store.approvals.push(approval); event(store, 'approval', `Approval requested: ${approval.action}`, { agentId: input.agentId, approvalId: approval.id, actor: 'workspace-user' }); writeStore(store);
      return json(res, 201, approval);
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if ((url.pathname === '/api/agent-events' || url.pathname === '/api/v1/events') && req.method === 'POST') {
    try {
      const input = await body(req);
      const eventType = input.event || input.eventType;
      const message = input.message || `${eventType || 'agent.event'} received from agent ${input.agentId || 'unknown'}`;
      if (!input.agentId || !eventType) return json(res, 400, { error: 'agentId and eventType are required' });
      const store = readStore();
      if (!store.agents.some(x => x.id === input.agentId)) {
        if (!input.agent || !input.agent.name || !input.agent.team || !Array.isArray(input.agent.tools)) return json(res, 404, { error: 'Unknown agent; include agent metadata to register it' });
        store.agents.push({ id: input.agentId, name: input.agent.name, team: input.agent.team, tools: input.agent.tools, status: 'healthy', createdAt: new Date().toISOString(), lastSeenAt: new Date().toISOString() });
      }
      const connectedAgent = store.agents.find(x => x.id === input.agentId);
      if (connectedAgent.archived) return json(res, 409, { error: 'Agent is archived; restore it before sending activity' });
      connectedAgent.status = 'healthy';
      connectedAgent.lastSeenAt = new Date().toISOString();
      if (['started', 'running', 'task.started', 'agent.started'].includes(eventType)) {
        connectedAgent.runtimeStatus = 'running';
        connectedAgent.lastActivityAt = connectedAgent.lastSeenAt;
        connectedAgent.currentTask = { id: input.taskId || input.actionRef || null, name: message };
      } else if (['completed', 'idle', 'waiting', 'task.completed', 'task.waiting', 'agent.completed'].includes(eventType)) {
        connectedAgent.runtimeStatus = 'running';
        connectedAgent.currentTask = null;
        connectedAgent.lastActivityAt = connectedAgent.lastSeenAt;
        connectedAgent.idleAfterAt = new Date(Date.now() + Number(process.env.AGENTGUARD_COMPLETION_GRACE_MS || 120000)).toISOString();
      } else if (eventType === 'failed' || eventType.endsWith('.failed')) {
        connectedAgent.runtimeStatus = 'failed';
      }
      if (eventType !== 'heartbeat') {
        const kind = ['failed', 'tool.blocked', 'policy.blocked'].includes(eventType) || eventType.endsWith('.failed') ? 'block' : eventType.includes('approval') ? 'approval' : 'action';
        event(store, kind, message, { agentId: input.agentId, eventType, actionRef: input.actionRef || null, runId: input.runId || null, taskId: input.taskId || null, tool: input.tool || null, resource: input.resource || null, eventStatus: input.status || null, durationMs: input.durationMs || null, sourceTimestamp: input.timestamp || null, metadata: input.metadata || null });
      }
      writeStore(store);
      return json(res, 201, { ok: true });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/policies/' && req.method === 'PATCH') return json(res, 404, { error: 'Missing policy id' });
  const policyMatch = url.pathname.match(/^\/api\/policies\/([^/]+)$/);
  const approvalMatch = url.pathname.match(/^\/api\/approvals\/([^/]+)\/(approve|deny)$/);
  try {
    if (policyMatch && req.method === 'PATCH') {
      if (!requireRole('configure')) return;
      const store = readStore(), policy = store.policies.find(x => x.id === policyMatch[1]);
      if (!policy) return json(res, 404, { error: 'Policy not found' });
      const input = await body(req);
      if (input.enabled !== undefined && typeof input.enabled !== 'boolean') return json(res, 400, { error: 'enabled must be boolean' });
      if (input.enabled !== undefined) policy.enabled = input.enabled;
      for (const field of ['name', 'scope', 'agentId', 'actionType', 'resourcePattern', 'effect', 'priority']) {
        if (input[field] === undefined) continue;
        if (field === 'effect' && !['allow', 'require_approval', 'block'].includes(input[field])) return json(res, 400, { error: 'Invalid policy effect' });
        if (field === 'priority' && !Number.isInteger(Number(input[field]))) return json(res, 400, { error: 'priority must be an integer' });
        if (field === 'agentId' && input[field] !== '*' && !store.agents.some(agent => agent.id === input[field])) return json(res, 404, { error: 'Unknown agent' });
        policy[field] = field === 'priority' ? Number(input[field]) : input[field];
      }
      policy.version = (policy.version || 1) + 1;
      policy.updatedAt = new Date().toISOString();
      event(store, 'action', `Policy updated: ${policy.name} (version ${policy.version})`, { policyId: policy.id, version: policy.version, actor: 'workspace-user' });
      writeStore(store); return json(res, 200, policy);
    }
    if (approvalMatch && req.method === 'POST') {
      if (!requireRole('review')) return;
      const store = readStore(), approval = store.approvals.find(x => x.id === approvalMatch[1]);
      if (!approval || approval.status !== 'pending') return json(res, 404, { error: 'Pending approval not found' });
      const decisionInput = await body(req);
      const agent = store.agents.find(x => x.id === approval.agentId);
      const decision = approvalMatch[2];
      approval.status = decision === 'approve' ? 'approved' : 'denied';
      approval.decision = decision;
      approval.decidedAt = new Date().toISOString();
      approval.decidedBy = decisionInput.decidedBy || 'workspace-user';
      approval.rationale = String(decisionInput.rationale || '').slice(0, 2000);
      event(store, decision === 'approve' ? 'action' : 'block', `${agent.name} was ${decision === 'approve' ? 'approved to' : 'denied permission to'} ${approval.action.toLowerCase()}.${approval.rationale ? ' Note: ' + approval.rationale : ''}`, { agentId: approval.agentId, actionRef: approval.actionRef, approvalId: approval.id, policyId: approval.policyId, decidedBy: approval.decidedBy, rationale: approval.rationale });
      writeStore(store); return json(res, 200, { decision, approvalId: approval.id });
    }
  } catch (error) { return json(res, 400, { error: error.message }); }

  const requested = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  const file = path.resolve(dist, requested);
  if (!file.startsWith(dist + path.sep) && file !== path.join(dist, 'index.html')) return json(res, 403, { error: 'Forbidden' });
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return json(res, 404, { error: 'Not found' });
  const extension = path.extname(file).toLowerCase();
  const type = ({ '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon' })[extension] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': type }); fs.createReadStream(file).pipe(res);
});
if (require.main === module) {
  initializeStore().then(() => {
    const poller = setInterval(() => {
      const store = readStore();
      for (const agent of store.agents.filter(item => item.connection?.mode === 'url-binding' && item.connection?.desiredState === 'running')) refreshManagedConnection(agent.id).catch(() => {});
      const heartbeatChanges = expireHeartbeats(store, Number(process.env.AGENTGUARD_HEARTBEAT_TIMEOUT_MS || 60_000));
      const activityChanges = expireRuntimeActivity(store, Number(process.env.AGENTGUARD_IDLE_TIMEOUT_MS || 60_000));
      if (heartbeatChanges || activityChanges) writeStore(store);
    }, managedPollMs);
    poller.unref();
    server.listen(port, () => console.log(`AgentGuard running at http://localhost:${port}`));
  }).catch(error => { console.error('Storage initialization failed:', error); process.exitCode = 1; });
}
module.exports = { server, normalizedRuntimeUrl, probeManagedAgent, runtimeUrlOwner };
