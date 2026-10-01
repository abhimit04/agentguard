const http = require('node:http');
const { once } = require('node:events');
const dns = require('node:dns').promises;
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, createHash, createHmac, createPrivateKey, sign: signBytes } = require('node:crypto');
if (fs.existsSync(path.join(__dirname, '.env'))) {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}
const { readStore, writeStore, initializeStore, postgresQuery, usePostgres } = require('./storage');
const { issueToken, tokenMatches, normalizeEnvelope, applyEnvelope, expireHeartbeats, expireRuntimeActivity } = require('./gateway');
const auth = require('./auth');
const { roles, roleFor, can, ensureBootstrapMembership } = require('./rbac');
const membershipRepository = require('./repositories/memberships');
const agentRepository = require('./repositories/agents');
const governanceRepository = require('./repositories/governance');
const telemetryRepository = require('./repositories/telemetry');
const auditRepository = require('./repositories/audit');
const retentionRepository = require('./repositories/retention');
const auditCursor = require('./audit-cursor');
const { verifyAuditPage } = require('./audit-integrity');
const { productionOriginErrors } = require('./deployment-config');

function publishTelemetry(result) {
  const store = readStore();
  const index = store.agents.findIndex(agent => agent.id === result.agent.id && agent.workspaceId === result.agent.workspaceId);
  if (index >= 0) store.agents[index] = result.agent;
  else store.agents.push(result.agent);
  store.events = [...result.events.slice().reverse(), ...store.events].slice(0, 1000);
  store.incidents.unshift(...result.incidents);
  store.alerts.unshift(...result.alerts);
  writeStore(store);
  if (alertWebhookUrl) for (const alert of result.alerts) void dispatchAlertDelivery(alert).catch(error => console.error('Telemetry alert delivery failed:', error.message));
}
function telemetryError(res, error) {
  const status = error.statusCode || 503;
  return json(res, status, { error: status === 503 ? 'Telemetry could not be committed; retry with the same eventId' : error.message });
}

const port = Number(process.env.PORT || 3100);
const dist = path.join(__dirname, 'dist');
const seed = { schemaVersion: 12, workspaces: [{ id: 'default', name: 'AgentGuard Workspace' }], companies: [{ id: 'default', workspaceId: 'default', name: 'Default workspace' }], agents: [], policies: [], approvals: [], assessments: [], incidents: [], alerts: [], events: [] };
const integrationApiKey = process.env.AGENTGUARD_API_KEY || '';
const requireAuth = process.env.AGENTGUARD_REQUIRE_AUTH === 'true';
const rateWindow = new Map();
let rateLimitRejections = 0;
let lastRateLimitPruneAt = 0;
const managedPollMs = Math.max(5000, Number(process.env.AGENTGUARD_CONNECTOR_POLL_MS || 15000));
const approvalTtlMs = Math.max(60_000, Number(process.env.AGENTGUARD_APPROVAL_TTL_MS || 15 * 60_000));
const uncertainExecutionAfterMs = Math.max(60_000, Number(process.env.AGENTGUARD_EXECUTION_UNCERTAIN_AFTER_MS || 5 * 60_000));
const coverageVerificationMs = Math.max(1, Math.min(720, Number(process.env.AGENTGUARD_COVERAGE_VERIFICATION_HOURS || 24))) * 60 * 60_000;
const alertWebhookUrl = process.env.AGENTGUARD_ALERT_WEBHOOK_URL || '';
const alertWebhookToken = process.env.AGENTGUARD_ALERT_WEBHOOK_TOKEN || '';
const auditSigningConfigured = Boolean(process.env.AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_FILE && process.env.AGENTGUARD_AUDIT_SIGNING_KEY_ID && fs.existsSync(path.resolve(__dirname, process.env.AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_FILE)));
function json(res, code, body, headers = {}) { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers }); res.end(JSON.stringify(body)); }
function redirect(res, location, headers = {}) { res.writeHead(302, { Location: location, ...headers }); res.end(); }
function secureHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https://lh3.googleusercontent.com; connect-src 'self'; form-action 'self' https://accounts.google.com");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
}
function authorizedIntegration(req) { return Boolean(integrationApiKey) && (req.headers.authorization === `Bearer ${integrationApiKey}` || req.headers['x-agentguard-api-key'] === integrationApiKey); }
function gatewayIdentity(req, store, requestedAgentId) {
  const companyId = String(req.headers['x-agentguard-company'] || '');
  const agentId = String(req.headers['x-agentguard-agent'] || requestedAgentId || '');
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const agent = store.agents.find(item => item.id === agentId && item.companyId === companyId);
  return agent && tokenMatches(token, agent.credentialHash) ? agent : null;
}
function enforcementCoverage(agent, events = [], policies = []) {
  const agentEvents = events.filter(item => item.agentId === agent.id);
  const recent = value => value && Date.now() - new Date(value).getTime() <= coverageVerificationMs;
  const latest = predicate => agentEvents.filter(predicate).sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))[0] || null;
  const telemetryEvent = latest(item => ['started', 'running', 'completed', 'tool.call', 'agent.running'].includes(item.eventType || item.event));
  const policyEvent = latest(item => ['policy.allowed', 'policy.blocked', 'policy.budget_blocked', 'approval.required', 'execution.claimed', 'execution.completed', 'execution.failed'].includes(item.eventType));
  const hasPolicy = policies.some(item => item.enabled !== false && (item.agentId === '*' || item.agentId === agent.id));
  const gateway = agent.connection?.mode === 'gateway' || agent.connection?.mode === 'managed-http';
  const healthStatus = recent(agent.lastSeenAt) ? 'verified' : agent.lastSeenAt ? 'stale' : gateway ? 'configured' : 'missing';
  const telemetryStatus = telemetryEvent && recent(telemetryEvent.createdAt) ? 'verified' : telemetryEvent || agent.telemetrySnapshot ? 'stale' : 'missing';
  const policyStatus = policyEvent && recent(policyEvent.createdAt) ? 'verified' : policyEvent ? 'stale' : hasPolicy ? 'configured' : 'missing';
  return {
    healthMonitoring: { status: healthStatus, evidence: agent.lastSeenAt ? `last seen ${agent.lastSeenAt}` : null },
    executionTelemetry: { status: telemetryStatus, evidence: telemetryEvent ? `runtime event ${telemetryEvent.createdAt}` : agent.telemetrySnapshot ? 'telemetry snapshot' : null },
    policyEnforcement: { status: policyStatus, evidence: policyEvent ? `policy/execution event ${policyEvent.createdAt}` : hasPolicy ? 'matching policy' : null },
    remoteIntervention: { status: gateway && agent.connection?.desiredState ? 'configured' : 'missing', evidence: gateway && agent.connection?.desiredState ? 'connection control' : null },
    verificationWindowHours: Math.round(coverageVerificationMs / 3_600_000),
    summary: [policyStatus === 'verified' ? 'policy enforcement recently verified' : policyStatus === 'stale' ? 'policy evidence is stale' : hasPolicy ? 'policy configured, unverified' : 'no policy evidence', telemetryStatus === 'verified' ? 'execution telemetry recently verified' : telemetryStatus === 'stale' ? 'execution telemetry is stale' : 'execution telemetry missing'].join('; ')
  };
}
function scoreRiskAssessment(agent, input) {
  const levels = { none: 0, low: 4, medium: 9, high: 15, critical: 20 };
  const autonomy = { assistive: 4, supervised: 10, autonomous: 18 }[agent.autonomy] ?? 10;
  const data = { public: 0, internal: 5, confidential: 12, restricted: 18 }[agent.dataClass] ?? 8;
  const impact = { low: 5, medium: 12, high: 20, critical: 25 }[input.impactLevel] ?? 12;
  const privacy = levels[input.privacyRisk] ?? 9;
  const bias = levels[input.biasRisk] ?? 9;
  const security = levels[input.securityRisk] ?? 9;
  const oversight = { strong: -10, partial: -4, none: 0 }[input.humanOversight] ?? 0;
  const contributions = { autonomy, dataSensitivity: data, impact, privacy, bias, security, verifiedHumanOversight: oversight };
  return { score: Math.max(0, Math.min(100, Object.values(contributions).reduce((sum, value) => sum + value, 0))), scoringModel: 'agentguard-risk-v1', contributions };
}
function boundedRateLimit(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? Math.min(parsed, 1_000_000) : fallback;
}
async function limited(req, { scope = null, identity = null, limit = null, weight = 1 } = {}) {
  const now = Date.now();
  const caller = String(identity || req.headers.authorization || req.headers['x-agentguard-api-key'] || req.headers['x-agentguard-agent'] || req.socket.remoteAddress || 'local');
  const route = req.url.split('?')[0];
  const bucketScope = scope || route;
  const key = `${bucketScope}:${createHash('sha256').update(caller).digest('hex').slice(0, 16)}`;
  const configuredLimit = boundedRateLimit(limit, boundedRateLimit(process.env.AGENTGUARD_RATE_LIMIT, 240));
  const requestWeight = Math.max(1, Math.min(500, Number(weight) || 1));
  if (usePostgres && process.env.AGENTGUARD_SHARED_RATE_LIMIT !== 'false') {
    const result = await postgresQuery(`INSERT INTO ag_rate_limit_buckets (scope, identity_hash, window_started, request_count)
      VALUES ($1,$2,date_trunc('minute', now()),$3)
      ON CONFLICT (scope, identity_hash, window_started) DO UPDATE SET request_count=ag_rate_limit_buckets.request_count+EXCLUDED.request_count, updated_at=now()
      RETURNING request_count`, [bucketScope, key, requestWeight]);
    // Buckets are only useful for the active minute. Prune expired entries so
    // a long-running multi-instance deployment does not retain caller history.
    if (now - lastRateLimitPruneAt > 60_000) {
      lastRateLimitPruneAt = now;
      void postgresQuery("DELETE FROM ag_rate_limit_buckets WHERE window_started < date_trunc('minute', now()) - interval '10 minutes'").catch(() => {});
    }
    const rejected = result.rows[0].request_count > configuredLimit;
    if (rejected) rateLimitRejections++;
    return rejected;
  }
  const windowStarted = now - (now % 60_000);
  const bucket = rateWindow.get(key);
  const current = bucket?.windowStarted === windowStarted ? bucket : { windowStarted, count: 0 };
  current.count += requestWeight;
  rateWindow.set(key, current);
  if (rateWindow.size > 10_000) for (const [entry, value] of rateWindow) if (value.windowStarted < windowStarted - 60_000) rateWindow.delete(entry);
  const rejected = current.count > configuredLimit;
  if (rejected) rateLimitRejections++;
  return rejected;
}
function rateLimited(res) { return json(res, 429, { error: 'Rate limit exceeded' }, { 'Retry-After': '60' }); }
function createAuditEvent(store, kind, message, metadata = {}) {
  const relatedAgent = metadata.agentId ? store.agents.find(item => item.id === metadata.agentId) : null;
  const relatedCompany = metadata.companyId ? store.companies.find(item => item.id === metadata.companyId) : null;
  return {
    ...metadata,
    workspaceId: metadata.workspaceId || relatedAgent?.workspaceId || relatedCompany?.workspaceId || 'default',
    id: randomUUID(),
    kind,
    message,
    createdAt: new Date().toISOString(),
    actor: metadata.actor || metadata.decidedBy || (metadata.agentId ? `agent:${metadata.agentId}` : 'system')
  };
}
function event(store, kind, message, metadata = {}) {
  const auditEvent = createAuditEvent(store, kind, message, metadata);
  store.events.unshift(auditEvent);
  const auditableFailure = kind === 'block' && ['policy.blocked', 'policy.budget_blocked', 'tool.permission_denied', 'approval.denied', 'approval.expired', 'connector.failed', 'failed'].some(type => auditEvent.eventType === type || String(auditEvent.eventType || '').endsWith('.failed'));
  if (!auditableFailure) return governanceRepository.appendEvent(auditEvent);
  const severity = ['policy.budget_blocked', 'tool.permission_denied', 'connector.failed'].includes(auditEvent.eventType) ? 'high' : 'medium';
  const incident = { id: randomUUID(), workspaceId: auditEvent.workspaceId, agentId: auditEvent.agentId || null, status: 'open', severity, title: message.slice(0, 240), sourceEventId: auditEvent.id, createdAt: auditEvent.createdAt, updatedAt: auditEvent.createdAt, timeline: [{ at: auditEvent.createdAt, actor: auditEvent.actor, note: 'Incident opened automatically from governance event.' }] };
  const alert = { id: randomUUID(), workspaceId: auditEvent.workspaceId, incidentId: incident.id, agentId: incident.agentId, status: 'open', severity, title: `New ${severity} incident: ${incident.title}`, createdAt: auditEvent.createdAt, channels: ['in-app'] };
  store.incidents.unshift(incident);
  (store.alerts ||= []).unshift(alert);
  if (usePostgres) {
    const persisted = governanceRepository.recordGovernanceSignal(auditEvent, severity).then(signals => {
      const eventIndex = store.events.findIndex(item => item.id === auditEvent.id);
      if (eventIndex >= 0) store.events[eventIndex] = signals.audit;
      const incidentIndex = store.incidents.findIndex(item => item.id === incident.id);
      if (incidentIndex >= 0) store.incidents[incidentIndex] = signals.incident;
      const alertIndex = store.alerts.findIndex(item => item.id === alert.id);
      if (alertIndex >= 0) store.alerts[alertIndex] = signals.alert;
      writeStore(store);
      if (alertWebhookUrl) void dispatchAlertDelivery(signals.alert).catch(error => console.error('Telemetry alert delivery failed:', error.message));
      return signals;
    }).catch(error => {
      store.events = store.events.filter(item => item.id !== auditEvent.id);
      store.incidents = store.incidents.filter(item => item.id !== incident.id);
      store.alerts = store.alerts.filter(item => item.id !== alert.id);
      throw error;
    });
    return persisted;
  }
  const persisted = Promise.all([governanceRepository.appendEvent(auditEvent), governanceRepository.upsertIncident(incident), governanceRepository.upsertAlert(alert)]);
  if (alertWebhookUrl) void dispatchAlertDelivery(alert);
  return persisted;
}
function validateProductionConfig() {
  if (process.env.NODE_ENV !== 'production') return;
  const missing = [];
  if (integrationApiKey.length < 32) missing.push('AGENTGUARD_API_KEY (minimum 32 characters)');
  if (process.env.AGENTGUARD_REQUIRE_AUTH !== 'true') missing.push('AGENTGUARD_REQUIRE_AUTH=true');
  if (!process.env.DATABASE_URL && process.env.AGENTGUARD_STORAGE !== 'postgres') missing.push('DATABASE_URL or AGENTGUARD_STORAGE=postgres');
  if (!process.env.OIDC_CLIENT_ID) missing.push('OIDC_CLIENT_ID');
  if (!process.env.OIDC_CLIENT_SECRET) missing.push('OIDC_CLIENT_SECRET');
  missing.push(...productionOriginErrors(process.env.AGENTGUARD_PUBLIC_ORIGIN, process.env.OIDC_REDIRECT_URI));
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) missing.push('JWT_SECRET (minimum 32 characters)');
  if (alertWebhookUrl && alertWebhookToken.length < 32) missing.push('AGENTGUARD_ALERT_WEBHOOK_TOKEN (minimum 32 characters when webhook delivery is enabled)');
  if (missing.length) throw new Error(`Unsafe production configuration: ${missing.join(', ')}`);
}
function workspaceIdFor(user, store = readStore()) {
  if (!user) return process.env.AGENTGUARD_DEFAULT_WORKSPACE_ID || 'default';
  const membership = store.memberships?.find(item => String(item.email || '').toLowerCase() === String(user.email || '').toLowerCase());
  if (membership?.workspaceId) return membership.workspaceId;
  const entry = (process.env.AGENTGUARD_WORKSPACE_MAP || '').split(',').map(item => item.trim().split('=')).find(([email]) => email && email.toLowerCase() === user.email.toLowerCase());
  return entry?.[1] || process.env.AGENTGUARD_DEFAULT_WORKSPACE_ID || 'default';
}
function requestContext(req) {
  const store = readStore(); const user = auth.session(req); const workspaceId = workspaceIdFor(user, store);
  const membershipCount = store.memberships?.length || 0;
  const membership = ensureBootstrapMembership(user, store, workspaceId);
  if ((store.memberships?.length || 0) !== membershipCount) writeStore(store);
  return { store, user, workspaceId, membership: membership || store.memberships?.find(item => item.workspaceId === workspaceId && String(item.email || '').toLowerCase() === String(user?.email || '').toLowerCase()) || null };
}
function workspaceForRequest(req) { return requestContext(req).workspaceId; }
function inWorkspace(item, workspaceId) { return (item.workspaceId || 'default') === workspaceId; }
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
function matchingPolicy(policies, workspaceId, agentId, actionType, resource) {
  const effectRank = { block: 3, require_approval: 2, allow: 1 };
  return policies
    .filter(policy => inWorkspace(policy, workspaceId) && policy.enabled && (policy.agentId === '*' || policy.agentId === agentId) && matchesPattern(policy.actionType, actionType) && matchesPattern(policy.resourcePattern, resource))
    .sort((a, b) => (b.priority ?? 100) - (a.priority ?? 100) || (effectRank[b.effect] ?? 0) - (effectRank[a.effect] ?? 0))[0] || null;
}
function toolPermission(agent, input) {
  if (input.actionType !== 'tool.call' && !input.tool) return { applies: false, allowed: true, tool: null };
  const resource = String(actionResource(input));
  const tool = String(input.tool || (resource.toLowerCase().startsWith('tool:') ? resource.slice(5) : '')).trim();
  const grants = Array.isArray(agent.tools) ? agent.tools.map(item => String(typeof item === 'string' ? item : item?.name || '').trim().replace(/^tool:/i, '')).filter(Boolean) : [];
  const allowed = Boolean(tool) && grants.some(grant => matchesPattern(grant, tool));
  return { applies: true, allowed, tool: tool || null, grants };
}
function actionResource(input) {
  if (input.resource) {
    const resource = String(input.resource);
    if (input.actionType === 'tool.call' && !input.tool && resource !== '*' && !resource.toLowerCase().startsWith('tool:')) return `tool:${resource}`;
    return resource;
  }
  return input.tool ? `tool:${input.tool}` : '*';
}
function normalizedBudget(input) {
  const maxTokens = input.maxTokens === '' || input.maxTokens === undefined ? null : Number(input.maxTokens);
  const maxCostUsd = input.maxCostUsd === '' || input.maxCostUsd === undefined ? null : Number(input.maxCostUsd);
  const dailyMaxTokens = input.dailyMaxTokens === '' || input.dailyMaxTokens === undefined ? null : Number(input.dailyMaxTokens);
  const dailyMaxCostUsd = input.dailyMaxCostUsd === '' || input.dailyMaxCostUsd === undefined ? null : Number(input.dailyMaxCostUsd);
  const dailyMaxActions = input.dailyMaxActions === '' || input.dailyMaxActions === undefined ? null : Number(input.dailyMaxActions);
  if ([maxTokens, dailyMaxTokens, dailyMaxActions].some(value => value !== null && (!Number.isInteger(value) || value < 1)) || [maxCostUsd, dailyMaxCostUsd].some(value => value !== null && (!Number.isFinite(value) || value <= 0))) throw new Error('Budget limits must be positive numbers');
  return { maxTokens, maxCostUsd, dailyMaxTokens, dailyMaxCostUsd, dailyMaxActions };
}
function exceedsBudget(policy, input) {
  if (!policy.maxTokens && !policy.maxCostUsd) return null;
  const tokens = input.estimatedTokens === undefined ? null : Number(input.estimatedTokens);
  const cost = input.estimatedCostUsd === undefined ? null : Number(input.estimatedCostUsd);
  if (policy.maxTokens && (!Number.isFinite(tokens) || tokens < 0)) return `Token estimate is required (limit ${policy.maxTokens})`;
  if (policy.maxCostUsd && (!Number.isFinite(cost) || cost < 0)) return `Cost estimate is required (limit $${policy.maxCostUsd})`;
  if (policy.maxTokens && tokens > policy.maxTokens) return `Estimated tokens ${tokens} exceed limit ${policy.maxTokens}`;
  if (policy.maxCostUsd && cost > policy.maxCostUsd) return `Estimated cost $${cost} exceeds limit $${policy.maxCostUsd}`;
  return null;
}
function usageReconciliation(events) {
  const estimates = new Map(); const actuals = new Map();
  for (const item of events) {
    if (!item.actionRef) continue;
    if ((item.eventType === 'policy.allowed' || item.eventType === 'approval.required') && (item.estimatedTokens !== undefined || item.estimatedCostUsd !== undefined)) estimates.set(item.actionRef, item);
    const metrics = item.metrics || item.metadata?.metrics;
    if (metrics && item.eventType && !item.eventType.startsWith('policy.') && !item.eventType.startsWith('approval.')) {
      const current = actuals.get(item.actionRef) || { tokens: 0, costUsd: 0, events: 0, agentId: item.agentId };
      current.tokens += Number(metrics.inputTokens || 0) + Number(metrics.outputTokens || 0);
      current.costUsd += Number(metrics.costUsd || 0); current.events++; actuals.set(item.actionRef, current);
    }
  }
  return [...estimates.entries()].map(([actionRef, estimate]) => {
    const actual = actuals.get(actionRef) || null;
    const estimatedTokens = estimate.estimatedTokens ?? null; const estimatedCostUsd = estimate.estimatedCostUsd ?? null;
    return { actionRef, agentId: estimate.agentId, action: estimate.message, createdAt: estimate.createdAt, estimatedTokens, estimatedCostUsd, actualTokens: actual?.tokens ?? null, actualCostUsd: actual?.costUsd ?? null, telemetryEvents: actual?.events || 0, tokenVariance: actual && estimatedTokens !== null ? actual.tokens - estimatedTokens : null, costVariance: actual && estimatedCostUsd !== null ? actual.costUsd - estimatedCostUsd : null, status: actual ? 'reconciled' : 'awaiting_telemetry' };
  }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}
function body(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    const maxBytes = Math.max(16_384, Number(process.env.AGENTGUARD_MAX_BODY_BYTES || 1_000_000));
    let rejected = false;
    req.on('data', chunk => {
      if (rejected) return;
      raw += chunk;
      if (Buffer.byteLength(raw, 'utf8') > maxBytes) {
        rejected = true;
        reject(Object.assign(new Error(`Request body exceeds ${maxBytes} bytes`), { statusCode: 413 }));
        req.resume();
      }
    });
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
function privateAddress(address) {
  return /^127\.|^10\.|^192\.168\.|^169\.254\.|^0\.|^::1$|^fc|^fd|^fe80:/i.test(address) || (() => { const match = address.match(/^172\.(\d+)\./); return match && Number(match[1]) >= 16 && Number(match[1]) <= 31; })();
}
async function validateRuntimeDestination(value) {
  const url = new URL(normalizedRuntimeUrl(value));
  const allowlist = new Set((process.env.AGENTGUARD_RUNTIME_HOST_ALLOWLIST || '').split(',').map(item => item.trim().toLowerCase()).filter(Boolean));
  if (allowlist.has(url.hostname.toLowerCase())) return;
  const localDevelopment = process.env.NODE_ENV !== 'production' && ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
  if (localDevelopment) return;
  const addresses = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(item => privateAddress(item.address))) throw new Error('Runtime URL resolves to a private or local address; add the host to AGENTGUARD_RUNTIME_HOST_ALLOWLIST when intentional');
}
async function dispatchAlertDelivery(alert) {
  if (!alertWebhookUrl) return null;
  if (usePostgres) {
    await governanceRepository.enqueueAlertDelivery(alert);
    const claimed = await governanceRepository.claimAlertDeliveries({ workspaceId: alert.workspaceId, alertId: alert.id, limit: 1 });
    if (!claimed?.length) {
      const previous = (await governanceRepository.listAlertDeliveries(alert.workspaceId))?.find(item => item.alertId === alert.id && item.status === 'delivered');
      return previous || { workspaceId: alert.workspaceId, alertId: alert.id, channel: 'webhook', status: 'queued' };
    }
    return sendClaimedAlertDelivery(claimed[0]);
  }
  const attemptedAt = new Date().toISOString();
  const delivery = { id: randomUUID(), workspaceId: alert.workspaceId, alertId: alert.id, channel: 'webhook', status: 'failed', attemptedAt };
  try {
    if (alertWebhookToken.length < 32) throw new Error('Webhook token is not configured securely');
    await validateRuntimeDestination(alertWebhookUrl);
    const payload = JSON.stringify({ event: 'agentguard.alert.opened', occurredAt: attemptedAt, data: alert });
    const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 5000);
    let response;
    try { response = await fetch(alertWebhookUrl, { method: 'POST', redirect: 'error', signal: controller.signal, headers: { 'content-type': 'application/json', 'x-agentguard-event': 'alert.opened', 'x-agentguard-signature': `sha256=${createHmac('sha256', alertWebhookToken).update(payload).digest('hex')}` }, body: payload }); } finally { clearTimeout(timeout); }
    if (!response.ok) { delivery.httpStatus = response.status; throw new Error(`Webhook returned HTTP ${response.status}`); }
    Object.assign(delivery, { status: 'delivered', httpStatus: response.status, deliveredAt: new Date().toISOString() });
  } catch (error) { delivery.errorMessage = error.message; }
  await Promise.all([
    governanceRepository.upsertAlertDelivery(delivery),
    governanceRepository.appendEvent({ id: randomUUID(), workspaceId: alert.workspaceId, agentId: alert.agentId, kind: delivery.status === 'delivered' ? 'action' : 'block', eventType: delivery.status === 'delivered' ? 'alert.webhook_delivered' : 'alert.webhook_failed', actor: 'system:alert-delivery', message: delivery.status === 'delivered' ? `Webhook alert delivered: ${alert.title}` : `Webhook alert delivery failed: ${delivery.errorMessage}`, createdAt: new Date().toISOString(), alertId: alert.id, deliveryId: delivery.id, httpStatus: delivery.httpStatus || null })
  ]);
  return delivery;
}
async function sendClaimedAlertDelivery(outbox) {
  const { alert } = outbox;
  const attemptedAt = new Date().toISOString();
  const delivery = { id: randomUUID(), workspaceId: outbox.workspaceId, alertId: outbox.alertId, channel: outbox.channel, status: 'failed', attemptedAt, attempt: outbox.attempts };
  try {
    if (alertWebhookToken.length < 32) throw new Error('Webhook token is not configured securely');
    await validateRuntimeDestination(alertWebhookUrl);
    const occurredAt = alert.createdAt || attemptedAt;
    const eventName = alert.notificationType === 'approval.required' ? 'agentguard.approval.required' : alert.notificationType === 'approval.expired' ? 'agentguard.approval.expired' : alert.notificationType === 'assessment.review_due' ? 'agentguard.assessment.review_due' : alert.notificationType === 'assessment.review_upcoming' ? 'agentguard.assessment.review_upcoming' : 'agentguard.alert.opened';
    const publicOrigin = String(process.env.AGENTGUARD_PUBLIC_ORIGIN || 'http://localhost:3100').replace(/\/$/, '');
    const data = alert.approvalId ? { ...alert, reviewUrl: `${publicOrigin}/#approvals` } : alert;
    const payload = JSON.stringify({ event: eventName, occurredAt, data });
    const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 5000);
    let response;
    try {
      response = await fetch(alertWebhookUrl, { method: 'POST', redirect: 'error', signal: controller.signal,
        headers: { 'content-type': 'application/json', 'x-agentguard-event': eventName, 'x-agentguard-idempotency-key': `${outbox.workspaceId}:${outbox.alertId}:webhook`, 'x-agentguard-signature': `sha256=${createHmac('sha256', alertWebhookToken).update(payload).digest('hex')}` }, body: payload });
    } finally { clearTimeout(timeout); }
    if (!response.ok) { delivery.httpStatus = response.status; throw new Error(`Webhook returned HTTP ${response.status}`); }
    Object.assign(delivery, { status: 'delivered', httpStatus: response.status, deliveredAt: new Date().toISOString() });
  } catch (error) { delivery.errorMessage = error.message; }
  const audit = { id: randomUUID(), workspaceId: outbox.workspaceId, agentId: alert.agentId || null,
    kind: delivery.status === 'delivered' ? 'action' : 'block',
    eventType: delivery.status === 'delivered' ? 'alert.webhook_delivered' : 'alert.webhook_failed',
    actor: 'system:alert-delivery',
    message: delivery.status === 'delivered' ? `Webhook alert delivered: ${alert.title}` : `Webhook alert attempt ${outbox.attempts} failed: ${delivery.errorMessage}`,
    createdAt: new Date().toISOString(), alertId: alert.id, deliveryId: delivery.id, attempt: outbox.attempts,
    httpStatus: delivery.httpStatus || null, errorMessage: delivery.errorMessage || null };
  const completed = await governanceRepository.finishAlertDelivery(outbox, delivery, audit);
  return completed.outcome === 'lease_lost' ? { ...delivery, status: 'queued', errorMessage: 'Delivery lease expired before result could be committed' } : completed.delivery;
}
async function drainAlertOutbox() {
  if (!usePostgres || !alertWebhookUrl) return;
  try {
    await governanceRepository.enqueueMissingAlertDeliveries();
    const jobs = await governanceRepository.claimAlertDeliveries({ limit: 10 });
    await Promise.allSettled(jobs.map(sendClaimedAlertDelivery));
  } catch (error) { console.error('Alert delivery outbox sweep failed:', error.message); }
}

function runtimeUrlOwner(store, runtimeUrl, exceptAgentId) {
  const normalized = normalizedRuntimeUrl(runtimeUrl);
  const workspaceId = store.agents.find(item => item.id === exceptAgentId)?.workspaceId || 'default';
  return store.agents.find(item => inWorkspace(item, workspaceId) && item.id !== exceptAgentId && !item.archived && item.connection?.desiredState === 'running' && item.connection?.runtimeUrl === normalized) || null;
}

async function probeManagedAgent(agent) {
  const connection = agent.connection || {};
  if (!connection.runtimeUrl) throw new Error('Add the agent runtime URL before starting');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    await validateRuntimeDestination(connection.runtimeUrl);
    const headers = { accept: 'application/json' };
    if (connection.authHeader) headers.authorization = connection.authHeader;
    const response = await fetch(connection.runtimeUrl, { method: 'GET', headers, signal: controller.signal, redirect: 'error' });
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
  let current = before.agents.find(item => item.id === agentId);
  if (usePostgres) current = await telemetryRepository.readAgent({ agentId, workspaceId: current?.workspaceId }, { integration: true });
  if (!current || current.archived || current.connection?.desiredState !== 'running') return null;
  if (usePostgres) {
    let snapshot, probeError;
    try {
      const agents = await agentRepository.list(current.workspaceId);
      const duplicateBindings = agents.filter(item => !item.archived && item.connection?.desiredState === 'running' && item.connection?.runtimeUrl === current.connection.runtimeUrl);
      if (duplicateBindings[0]?.id !== current.id) throw Object.assign(new Error('API URL is already bound to another active agent'), { runtimeProbe: true });
    } catch (error) { if (!error.runtimeProbe) throw error; probeError = error; }
    if (!probeError) try { snapshot = await probeManagedAgent(current); } catch (error) { probeError = error; }
    const result = await telemetryRepository.updateRuntime({ agentId, workspaceId: current.workspaceId, companyId: current.companyId }, (agent, addEvent) => {
      if (agent.archived || agent.connection?.desiredState !== 'running' || agent.connection?.runtimeUrl !== current.connection.runtimeUrl) return false;
      const wasConnected = agent.status === 'healthy';
      if (probeError) {
        agent.status = 'registered';
        agent.connection = { ...agent.connection, state: 'error', lastError: probeError.message, lastCheckedAt: new Date().toISOString() };
        if (wasConnected || recordEvent) addEvent('block', `Connector check failed for ${agent.name}: ${probeError.message}`, { eventType: 'connector.failed', actor: 'connector:managed-http' });
      } else {
        const changed = JSON.stringify(agent.telemetrySnapshot || null) !== JSON.stringify(snapshot);
        agent.status = 'healthy'; agent.lastSeenAt = new Date().toISOString(); agent.telemetrySnapshot = snapshot;
        agent.connection = { ...agent.connection, state: 'connected', lastError: null, lastCheckedAt: agent.lastSeenAt };
        if (recordEvent || !wasConnected) addEvent('action', `Managed connector started: ${agent.name}`, { eventType: 'connector.connected', metadata: snapshot, actor: 'connector:managed-http' });
        if (wasConnected && changed) addEvent('action', typeof snapshot.message === 'string' ? snapshot.message : `${agent.name} reported ${snapshot.status || snapshot.runtimeStatus || 'activity update'}`, { eventType: 'agent.activity', status: snapshot.status || snapshot.runtimeStatus, currentTask: snapshot.currentTask || null, metadata: snapshot, actor: `agent:${agent.id}` });
      }
    });
    publishTelemetry(result);
    if (probeError) throw probeError;
    return result.agent;
  }
  try {
    const duplicateBindings = before.agents.filter(item => inWorkspace(item, current.workspaceId || 'default') && !item.archived && item.connection?.desiredState === 'running' && item.connection?.runtimeUrl === current.connection.runtimeUrl);
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
    await agentRepository.upsert(agent);
    writeStore(store);
    return agent;
  } catch (error) {
    const store = readStore();
    const agent = store.agents.find(item => item.id === agentId);
    if (!agent) return null;
    const wasConnected = agent.status === 'healthy';
    agent.status = 'registered';
    agent.connection = { ...agent.connection, state: 'error', lastError: error.message, lastCheckedAt: new Date().toISOString() };
    if (wasConnected || recordEvent) await event(store, 'block', `Connector check failed for ${agent.name}: ${error.message}`, { agentId, eventType: 'connector.failed', actor: 'connector:managed-http' });
    await agentRepository.upsert(agent);
    writeStore(store);
    throw error;
  }
}

const server = http.createServer(async (req, res) => {
  secureHeaders(res);
  const url = new URL(req.url, 'http://localhost');
  const requireRole = permission => {
    if (!requireAuth) return true;
    const { user, store, workspaceId } = requestContext(req);
    if (!user) { json(res, 401, { error: 'Authentication required', login: '/auth/login' }); return false; }
    if (!can(user, permission, store, workspaceId)) { json(res, 403, { error: `Role ${roleFor(user, store, workspaceId) || 'none'} cannot perform this action` }); return false; }
    return true;
  };
  if (url.pathname === '/auth/login' && req.method === 'GET') return auth.login(res);
  if (url.pathname === '/auth/callback' && req.method === 'GET') { try { return await auth.callback(req, res, url.searchParams.get('code'), url.searchParams.get('state')); } catch (error) { console.error('Google auth callback failed:', error.message, error.cause?.message || ''); return json(res, 500, { error: 'Authentication failed', detail: process.env.NODE_ENV === 'production' ? undefined : error.message }); } }
  if (url.pathname === '/auth/logout' && req.method === 'GET') return auth.logout(req, res);
  if (url.pathname === '/api/session' && req.method === 'GET') { const { user, store, workspaceId, membership } = requestContext(req); const workspace = store.workspaces.find(item => item.id === workspaceId) || { id: workspaceId, name: workspaceId }; return json(res, 200, { authenticated: Boolean(user), user, role: roleFor(user, store, workspaceId), workspace, membership: membership ? { id: membership.id, role: membership.role } : null }); }
  if (url.pathname === '/api/workspace/members' && req.method === 'GET') {
    if (!requireRole('manageMembers')) return;
    const { store, workspaceId } = requestContext(req);
    let members = await membershipRepository.list(workspaceId);
    if (members && !members.length && store.memberships.some(item => item.workspaceId === workspaceId)) {
      for (const member of store.memberships.filter(item => item.workspaceId === workspaceId)) {
        const audit = createAuditEvent(store, 'action', `Workspace membership imported: ${member.email} (${member.role})`, { workspaceId, eventType: 'workspace.member.imported', actor: 'system:compatibility-import' });
        try { const saved = await membershipRepository.addWithAudit(member, audit); store.events.unshift(saved.audit); }
        catch (error) { if (error.code !== '23505') return json(res, 503, { error: 'Workspace membership import could not be committed', detail: error.message }); }
      }
      members = await membershipRepository.list(workspaceId);
      writeStore(store);
    }
    return json(res, 200, (members || store.memberships.filter(item => item.workspaceId === workspaceId)).map(({ subject, ...member }) => member));
  }
  if (url.pathname === '/api/workspace/members' && req.method === 'POST') {
    if (!requireRole('manageMembers')) return;
    try {
      const input = await body(req); const email = String(input.email || '').trim().toLowerCase(); const role = String(input.role || 'viewer');
      if (!/^\S+@\S+\.\S+$/.test(email) || !roles.includes(role)) return json(res, 400, { error: 'A valid email and role are required' });
      const context = requestContext(req); const store = structuredClone(context.store); const { workspaceId, user } = context;
      const currentMembers = usePostgres ? await membershipRepository.list(workspaceId) : store.memberships.filter(item => item.workspaceId === workspaceId);
      if (currentMembers.some(item => item.email === email)) return json(res, 409, { error: 'This user already belongs to the workspace' });
      const member = { id: randomUUID(), workspaceId, email, name: String(input.name || email).trim(), role, createdAt: new Date().toISOString(), invitedBy: user?.email || 'workspace-user', source: 'workspace-admin' };
      const audit = createAuditEvent(store, 'action', `Workspace member added: ${email} (${role})`, { workspaceId, eventType: 'workspace.member.added', actor: user?.email || 'workspace-user' });
      if (usePostgres) {
        const saved = await membershipRepository.addWithAudit(member, audit);
        store.memberships.push(saved.member); store.events.unshift(saved.audit);
      } else {
        const persisted = await membershipRepository.create(member);
        store.memberships.push(persisted || member); await event(store, 'action', audit.message, audit);
      }
      writeStore(store); return json(res, 201, member);
    } catch (error) { return json(res, error.statusCode || (usePostgres && error.code === '23505' ? 409 : usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const memberMatch = url.pathname.match(/^\/api\/workspace\/members\/([^/]+)$/);
  if (memberMatch && (req.method === 'PATCH' || req.method === 'DELETE')) {
    if (!requireRole('manageMembers')) return;
    try {
      const context = requestContext(req); const store = structuredClone(context.store); const { workspaceId, user } = context;
      const members = usePostgres ? await membershipRepository.list(workspaceId) : store.memberships.filter(item => item.workspaceId === workspaceId);
      const member = members.find(item => item.id === memberMatch[1] && item.workspaceId === workspaceId);
      if (!member) return json(res, 404, { error: 'Workspace member not found' });
      if (req.method === 'DELETE') {
        if (!usePostgres && member.role === 'owner' && members.filter(item => item.role === 'owner').length === 1) return json(res, 409, { error: 'Assign another owner before removing the last owner' });
        const audit = createAuditEvent(store, 'action', `Workspace member removed: ${member.email}`, { workspaceId, eventType: 'workspace.member.removed', actor: user?.email || 'workspace-user' });
        if (usePostgres) {
          const removed = await membershipRepository.removeWithAudit(member.id, workspaceId, audit);
          if (!removed) return json(res, 404, { error: 'Workspace member not found' });
          store.events.unshift(removed.audit);
        } else {
          const deleted = await membershipRepository.remove(member.id, workspaceId);
          if (deleted === false) return json(res, 404, { error: 'Workspace member not found' });
          await event(store, 'action', audit.message, audit);
        }
        store.memberships = store.memberships.filter(item => item.id !== member.id); writeStore(store); return json(res, 204, {});
      }
      const input = await body(req); const role = String(input.role || '');
      if (!roles.includes(role)) return json(res, 400, { error: 'Invalid role' });
      if (!usePostgres && member.role === 'owner' && role !== 'owner' && members.filter(item => item.role === 'owner').length === 1) return json(res, 409, { error: 'Assign another owner before changing the last owner' });
      const audit = createAuditEvent(store, 'action', `Workspace role updated: ${member.email} is now ${role}`, { workspaceId, eventType: 'workspace.member.role_updated', actor: user?.email || 'workspace-user' });
      if (usePostgres) {
        const saved = await membershipRepository.updateRoleWithAudit(member.id, workspaceId, role, audit);
        if (!saved) return json(res, 404, { error: 'Workspace member not found' });
        Object.assign(member, saved.member); store.events.unshift(saved.audit);
      } else {
        const persisted = await membershipRepository.updateRole(member.id, workspaceId, role);
        if (persisted === null) return json(res, 404, { error: 'Workspace member not found' });
        Object.assign(member, persisted); await event(store, 'action', audit.message, audit);
      }
      const index = store.memberships.findIndex(item => item.id === member.id && item.workspaceId === workspaceId);
      if (index >= 0) store.memberships[index] = member; else store.memberships.push(member);
      writeStore(store); return json(res, 200, member);
    } catch (error) { return json(res, error.statusCode || (usePostgres && error.code === '23505' ? 409 : usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  if (url.pathname === '/api/companies' && req.method === 'GET') {
    if (!requireRole('read')) return;
    const workspaceId = workspaceForRequest(req);
    return json(res, 200, publicCompanies(readStore().companies.filter(item => inWorkspace(item, workspaceId))));
  }
  if (url.pathname === '/api/companies' && req.method === 'POST') {
    if (!requireRole('configure')) return;
    try {
      const input = await body(req); const name = String(input.name || '').trim();
      const requestedId = String(input.id || '').trim().toLowerCase();
      const baseId = requestedId || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
      if (!name || !baseId || !/^[a-z0-9][a-z0-9._-]{1,63}$/.test(baseId)) return json(res, 400, { error: 'Valid company name is required' });
      const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req); const companies = usePostgres ? await agentRepository.listCompanies(workspaceId) : store.companies.filter(company => inWorkspace(company, workspaceId)); let id = baseId; let suffix = 2;
      while (companies.some(company => company.id === id)) id = `${baseId.slice(0, 63 - String(suffix).length - 1)}-${suffix++}`;
      const credential = issueToken(); const now = new Date().toISOString(); const company = { id, workspaceId, name, gatewayCredentialHash: credential.hash, createdAt: now, updatedAt: now };
      const audit = createAuditEvent(store, 'action', `Company registered: ${name}`, { workspaceId, companyId: id, eventType: 'company.registered', actor: 'workspace-user' });
      if (usePostgres) {
        const saved = await agentRepository.saveCompanyWithAudit(company, audit, { create: true });
        Object.assign(company, saved.company); store.companies.push(company); store.events.unshift(saved.audit);
      } else {
        store.companies.push(company); await agentRepository.upsertCompany(company); await event(store, 'action', audit.message, audit);
      }
      writeStore(store);
      return json(res, 201, { id, name, gatewayCredential: credential.token });
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const companyCredentialMatch = url.pathname.match(/^\/api\/companies\/([^/]+)\/gateway-credentials$/);
  if (companyCredentialMatch && req.method === 'POST') {
    if (!requireRole('configure')) return;
    try {
      const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req); const companyId = decodeURIComponent(companyCredentialMatch[1]);
      const company = usePostgres ? await agentRepository.getCompany(workspaceId, companyId) : store.companies.find(item => item.id === companyId && inWorkspace(item, workspaceId));
      if (!company) return json(res, 404, { error: 'Company not found' });
      const expectedUpdatedAt = company.updatedAt; const credential = issueToken(); company.gatewayCredentialHash = credential.hash; company.updatedAt = new Date().toISOString();
      const audit = createAuditEvent(store, 'action', `Company gateway credential rotated: ${company.name}`, { workspaceId, companyId: company.id, eventType: 'company.credential_rotated', actor: 'workspace-user' });
      if (usePostgres) {
        const saved = await agentRepository.saveCompanyWithAudit(company, audit, { expectedUpdatedAt });
        Object.assign(company, saved.company); store.events.unshift(saved.audit);
      } else {
        await agentRepository.upsertCompany(company); await event(store, 'action', audit.message, audit);
      }
      const index = store.companies.findIndex(item => item.id === company.id && inWorkspace(item, workspaceId));
      if (index >= 0) store.companies[index] = company; else store.companies.push(company);
      writeStore(store);
      return json(res, 201, { companyId: company.id, gatewayCredential: credential.token });
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
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
      const store = structuredClone(readStore()); const workspaceId = String(input.workspaceId || input.workspace_id || process.env.AGENTGUARD_DEFAULT_WORKSPACE_ID || 'default'); let company = usePostgres ? await agentRepository.getCompany(workspaceId, companyId) : store.companies.find(item => item.id === companyId && inWorkspace(item, workspaceId)); const expectedUpdatedAt = company?.updatedAt || null; const credential = issueToken(); const now = new Date().toISOString();
      if (company) { company = { ...company, name, gatewayCredentialHash: credential.hash, updatedAt: now }; }
      else { company = { id: companyId, workspaceId, name, gatewayCredentialHash: credential.hash, createdAt: now, updatedAt: now }; }
      const audit = createAuditEvent(store, 'action', `Company gateway provisioned: ${name}`, { workspaceId, companyId, eventType: company.createdAt === now ? 'company.gateway_provisioned' : 'company.gateway_credential_rotated', actor: 'gateway:registry' });
      if (usePostgres) {
        const saved = await agentRepository.saveCompanyWithAudit(company, audit, company.createdAt === now ? { create: true } : { expectedUpdatedAt });
        Object.assign(company, saved.company); store.events.unshift(saved.audit);
      } else {
        await agentRepository.upsertCompany(company); await event(store, 'action', audit.message, audit);
      }
      const index = store.companies.findIndex(item => item.id === company.id && inWorkspace(item, workspaceId));
      if (index >= 0) store.companies[index] = company; else store.companies.push(company);
      writeStore(store);
      return json(res, 201, { companyId, companyName: name, gatewayCredential: credential.token, configEndpoint: '/api/gateway/config' });
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  if (url.pathname === '/api/gateway/agents/register' && req.method === 'POST') {
    if (!authorizedIntegration(req)) return json(res, 401, { error: 'Company onboarding credential required' });
    try {
      const input = await body(req);
      const companyId = String(input.companyId || input.company_id || '').trim();
      const name = String(input.agentName || input.agent_name || input.name || '').trim();
      if (!companyId || !name) return json(res, 400, { error: 'companyId and agentName are required' });
      const store = structuredClone(readStore());
      const agentId = generateAgentId(store);
      const workspaceId = String(input.workspaceId || input.workspace_id || process.env.AGENTGUARD_DEFAULT_WORKSPACE_ID || 'default');
      let company = store.companies.find(item => item.id === companyId && inWorkspace(item, workspaceId));
      if (!company) company = { id: companyId, workspaceId, name: input.companyName || input.company_name || companyId, createdAt: new Date().toISOString() };
      const credential = issueToken();
      const runtimeUrl = input.runtimeUrl || input.runtime_url || null;
      const now = new Date().toISOString();
      const agent = { id: agentId, workspaceId, companyId, name, agentType: input.agentType || input.agent_type || 'general', framework: input.framework || 'unknown', model: input.model || null, version: input.version || null, team: input.team || 'Unassigned', tools: Array.isArray(input.tools) ? input.tools : [], parentId: input.parentId || input.parent_id || null, riskTier: input.riskTier || 'unassessed', dataClass: input.dataClass || 'internal', autonomy: input.autonomy || 'assistive', status: 'registered', runtimeStatus: 'offline', createdAt: now, updatedAt: now, lastSeenAt: null, credentialHash: credential.hash, connection: { mode: 'gateway', runtimeUrl: runtimeUrl ? normalizedRuntimeUrl(runtimeUrl) : null, desiredState: 'running', state: 'awaiting_telemetry' } };
      if (usePostgres) {
        const companyAudit = createAuditEvent(store, 'action', `Company gateway provisioned: ${company.name}`, { workspaceId, companyId, actor: 'gateway:registry' });
        const agentAudit = createAuditEvent(store, 'action', `Agent registered through gateway: ${agent.name}`, { workspaceId, agentId, companyId, actor: 'gateway:registry' });
        const saved = await agentRepository.registerGatewayAgent(company, agent, companyAudit, agentAudit);
        company = saved.company;
        const companyIndex = store.companies.findIndex(item => item.id === company.id && inWorkspace(item, workspaceId));
        if (companyIndex >= 0) store.companies[companyIndex] = company; else store.companies.push(company);
        store.agents.push(saved.agent); store.events.unshift(saved.audit);
        if (saved.companyCreated) store.events.unshift(saved.companyAudit);
      } else {
        if (!store.companies.some(item => item.id === company.id && inWorkspace(item, workspaceId))) store.companies.push(company);
        await agentRepository.upsertCompany(company);
        store.agents.push(agent); await agentRepository.upsert(agent); event(store, 'action', `Agent registered through gateway: ${agent.name}`, { agentId, companyId, actor: 'gateway:registry' });
      }
      writeStore(store);
      return json(res, 201, { companyId, agentId, gatewayCredential: credential.token, endpoints: { status: `/api/gateway/agents/${encodeURIComponent(agentId)}/status`, heartbeat: `/api/gateway/agents/${encodeURIComponent(agentId)}/heartbeat`, events: `/api/gateway/agents/${encodeURIComponent(agentId)}/events`, health: `/api/gateway/agents/${encodeURIComponent(agentId)}/health`, otlp: 'http://localhost:4318' } });
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const gatewayAgentMatch = url.pathname.match(/^\/api\/gateway\/agents\/([^/]+)\/(status|heartbeat|events|health)$/);
  if (gatewayAgentMatch) {
    const agentId = decodeURIComponent(gatewayAgentMatch[1]);
    const operation = gatewayAgentMatch[2];
    if (usePostgres) {
      try {
        if (req.headers['x-agentguard-agent'] && req.headers['x-agentguard-agent'] !== agentId) return json(res, 403, { error: 'Agent header does not match request path' });
        if (!req.headers['x-agentguard-company']) return json(res, 401, { error: 'Company identity required' });
        const identity = { agentId, companyId: String(req.headers['x-agentguard-company']), workspaceId: req.headers['x-agentguard-workspace'] || null };
        const credential = { token: String(req.headers.authorization || '').replace(/^Bearer\s+/i, '') };
        const agent = await telemetryRepository.readAgent(identity, credential);
        if (['status', 'health'].includes(operation) && req.method === 'GET') return json(res, 200, { companyId: agent.companyId, agentId: agent.id, status: agent.runtimeStatus || 'offline', health: agent.status === 'healthy' ? 'healthy' : 'offline', currentTask: agent.currentTask || null, lastHeartbeat: agent.lastSeenAt, version: agent.version || null, usage: agent.usage || null });
        if (['heartbeat', 'events'].includes(operation) && req.method === 'POST') {
          const companyLimit = Number(process.env.AGENTGUARD_COMPANY_RATE_LIMIT || Number(process.env.AGENTGUARD_RATE_LIMIT || 240) * 10);
          const agentLimit = Number(process.env.AGENTGUARD_AGENT_RATE_LIMIT || process.env.AGENTGUARD_RATE_LIMIT || 240);
          const workspaceLimit = boundedRateLimit(process.env.AGENTGUARD_WORKSPACE_RATE_LIMIT, companyLimit * 10);
          if (await limited(req, { scope: `telemetry:workspace:${operation}`, identity: agent.workspaceId, limit: workspaceLimit }) || await limited(req, { scope: `telemetry:company:${operation}`, identity: agent.companyId, limit: companyLimit }) || await limited(req, { scope: `telemetry:agent:${operation}`, identity: `${agent.companyId}:${agent.id}`, limit: agentLimit })) return rateLimited(res);
          const input = await body(req);
          if ((input.agentId && input.agentId !== agentId) || (input.companyId && input.companyId !== agent.companyId)) return json(res, 403, { error: 'Telemetry identity conflicts with the request path' });
          let envelope;
          try { envelope = normalizeEnvelope({ ...input, companyId: agent.companyId, agentId, eventType: operation === 'heartbeat' ? 'heartbeat' : input.eventType || input.event }); }
          catch (error) { return json(res, 400, { error: error.message }); }
          const result = await telemetryRepository.ingest(identity, [envelope], credential);
          publishTelemetry(result);
          return json(res, 202, { accepted: result.accepted, duplicate: Boolean(result.duplicates), status: result.agent.runtimeStatus });
        }
        return json(res, 405, { error: 'Method not allowed' });
      } catch (error) { return telemetryError(res, error); }
    }
    const store = readStore();
    const agent = gatewayIdentity(req, store, agentId);
    if (!agent) return json(res, 401, { error: 'Invalid company or agent credential' });
    if ((operation === 'status' || operation === 'health') && req.method === 'GET') return json(res, 200, { companyId: agent.companyId, agentId: agent.id, status: agent.runtimeStatus || 'offline', health: agent.status === 'healthy' ? 'healthy' : 'offline', currentTask: agent.currentTask || null, lastHeartbeat: agent.lastSeenAt, version: agent.version || null, usage: agent.usage || null });
    if ((operation === 'heartbeat' || operation === 'events') && req.method === 'POST') {
      try {
        const companyLimit = Number(process.env.AGENTGUARD_COMPANY_RATE_LIMIT || Number(process.env.AGENTGUARD_RATE_LIMIT || 240) * 10);
        const agentLimit = Number(process.env.AGENTGUARD_AGENT_RATE_LIMIT || process.env.AGENTGUARD_RATE_LIMIT || 240);
        const workspaceLimit = boundedRateLimit(process.env.AGENTGUARD_WORKSPACE_RATE_LIMIT, companyLimit * 10);
        if (await limited(req, { scope: `telemetry:workspace:${operation}`, identity: agent.workspaceId, limit: workspaceLimit }) || await limited(req, { scope: `telemetry:company:${operation}`, identity: agent.companyId, limit: companyLimit }) || await limited(req, { scope: `telemetry:agent:${operation}`, identity: `${agent.companyId}:${agent.id}`, limit: agentLimit })) return rateLimited(res);
        const input = await body(req);
        const envelope = normalizeEnvelope({ ...input, companyId: agent.companyId, agentId: agent.id, eventType: operation === 'heartbeat' ? 'heartbeat' : input.eventType || input.event });
        const result = applyEnvelope(store, envelope, event); await agentRepository.upsert(result.agent); await governanceRepository.flushAudit(); writeStore(store);
        return json(res, 202, { accepted: result.duplicate ? 0 : 1, duplicate: result.duplicate, status: result.agent.runtimeStatus });
      } catch (error) { return json(res, error.statusCode || 400, { error: error.message }); }
    }
    return json(res, 405, { error: 'Method not allowed' });
  }
  if (url.pathname === '/api/gateway/events' && req.method === 'POST') {
    if (await limited(req)) return rateLimited(res);
    try {
      const input = await body(req);
      const envelopes = (Array.isArray(input) ? input : [input]).map(normalizeEnvelope);
      if (!envelopes.length || envelopes.length > 500) return json(res, 400, { error: 'Send between 1 and 500 telemetry events' });
      const companyId = req.headers['x-agentguard-company'] || envelopes[0].companyId;
      const agentId = req.headers['x-agentguard-agent'] || envelopes[0].agentId;
      if (envelopes.some(item => item.companyId !== companyId || item.agentId !== agentId)) return json(res, 400, { error: 'A gateway batch must contain one company and one agent identity' });
      const companyLimit = Number(process.env.AGENTGUARD_COMPANY_RATE_LIMIT || Number(process.env.AGENTGUARD_RATE_LIMIT || 240) * 10);
      const agentLimit = Number(process.env.AGENTGUARD_AGENT_RATE_LIMIT || process.env.AGENTGUARD_RATE_LIMIT || 240);
      const workspaceId = req.headers['x-agentguard-workspace'] || 'default';
      const workspaceLimit = boundedRateLimit(process.env.AGENTGUARD_WORKSPACE_RATE_LIMIT, companyLimit * 10);
      const eventWeight = envelopes.length;
      if (await limited(req, { scope: 'telemetry:workspace:batch', identity: workspaceId, limit: workspaceLimit, weight: eventWeight }) || await limited(req, { scope: 'telemetry:company:batch', identity: companyId, limit: companyLimit, weight: eventWeight }) || await limited(req, { scope: 'telemetry:agent:batch', identity: `${companyId}:${agentId}`, limit: agentLimit, weight: eventWeight })) return rateLimited(res);
      if (usePostgres) {
        try {
          const result = await telemetryRepository.ingest({ companyId, agentId, workspaceId: req.headers['x-agentguard-workspace'] || null }, envelopes,
            { token: String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''), company: true, integration: authorizedIntegration(req) });
          publishTelemetry(result);
          return json(res, 202, { accepted: result.accepted, duplicates: result.duplicates, agentId, companyId });
        } catch (error) { return telemetryError(res, error); }
      }
      const store = readStore();
      const agent = store.agents.find(item => item.id === agentId && item.companyId === companyId);
      const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const trustedGateway = Boolean(integrationApiKey) && authorizedIntegration(req);
      const company = store.companies.find(item => item.id === companyId);
      const trustedCompany = company && tokenMatches(token, company.gatewayCredentialHash);
      if (!agent || (!trustedGateway && !trustedCompany && !tokenMatches(token, agent.credentialHash))) return json(res, 401, { error: 'Invalid company, gateway, or agent credential' });
      let accepted = 0, duplicates = 0;
      for (const envelope of envelopes) { const result = applyEnvelope(store, envelope, event); await agentRepository.upsert(result.agent); result.duplicate ? duplicates++ : accepted++; }
      await governanceRepository.flushAudit(); writeStore(store);
      return json(res, 202, { accepted, duplicates, agentId, companyId });
    } catch (error) { return json(res, error.statusCode || 400, { error: error.message }); }
  }
  const integrationRoute = ['/api/agent-events', '/api/v1/events', '/api/guard/check', '/api/guard/executions/claim', '/api/guard/executions/complete'].includes(url.pathname);
  if (integrationRoute && await limited(req)) return rateLimited(res);
  if (integrationRoute && !authorizedIntegration(req)) return json(res, 401, { error: 'AgentGuard integration API key required' });
  if (url.pathname === '/api/health') return json(res, 200, { ok: true });
  if (url.pathname === '/api/audit/retention' && req.method === 'GET') {
    if (!requireRole('read')) return;
    if (!usePostgres) return json(res, 503, { error: 'Retention settings require PostgreSQL' });
    try { return json(res, 200, await retentionRepository.previewRetention(workspaceForRequest(req))); }
    catch (error) { return json(res, 503, { error: 'Retention settings could not be loaded' }); }
  }
  if (url.pathname === '/api/audit/retention' && req.method === 'PUT') {
    if (!requireRole('configure')) return;
    if (!usePostgres) return json(res, 503, { error: 'Retention settings require PostgreSQL' });
    try {
      const input = await body(req);
      const days = Number(input.retentionDays);
      const expectedVersion = Number(input.version);
      if (!Number.isInteger(days) || days < 30 || days > 3650 || !Number.isSafeInteger(expectedVersion) || expectedVersion < 0)
        return json(res, 400, { error: 'Retention must be 30–3650 whole days and include the current version' });
      const { store, workspaceId, user } = requestContext(req);
      const actor = user?.email || 'workspace-user';
      const audit = createAuditEvent(store, 'action', `Audit retention configured: ${days} days`,
        { workspaceId, eventType: 'audit.retention.configured', actor, retentionDays: days, previousVersion: expectedVersion });
      const saved = await retentionRepository.saveRetentionWithAudit(workspaceId, days, expectedVersion, actor, audit);
      return saved ? json(res, 200, await retentionRepository.previewRetention(workspaceId)) : json(res, 404, { error: 'Workspace not found' });
    } catch (error) { return json(res, error.statusCode || 503, { error: error.message }); }
  }
  if (url.pathname === '/api/audit/legal-holds' && req.method === 'GET') {
    if (!requireRole('read')) return;
    if (!usePostgres) return json(res, 503, { error: 'Legal holds require PostgreSQL' });
    try { return json(res, 200, await retentionRepository.listHolds(workspaceForRequest(req))); }
    catch (error) { return json(res, 503, { error: 'Legal holds could not be loaded' }); }
  }
  if (url.pathname === '/api/audit/legal-holds' && req.method === 'POST') {
    if (!requireRole('createLegalHold')) return;
    if (!usePostgres) return json(res, 503, { error: 'Legal holds require PostgreSQL' });
    try {
      const input = await body(req);
      const reason = String(input.reason || '').trim();
      const caseReference = String(input.caseReference || '').trim();
      if (reason.length < 8 || reason.length > 2000 || caseReference.length > 200) return json(res, 400, { error: 'Reason must be 8–2000 characters; case reference must be at most 200 characters' });
      const { store, workspaceId, user } = requestContext(req);
      const actor = user?.email || 'workspace-user';
      const hold = { id: randomUUID(), workspaceId, reason, caseReference, createdBy: actor, createdAt: new Date().toISOString() };
      const audit = createAuditEvent(store, 'action', `Audit legal hold created: ${hold.id}`, { workspaceId, eventType: 'audit.legal_hold.created', actor, holdId: hold.id, reason, caseReference });
      return json(res, 201, (await retentionRepository.createHoldWithAudit(hold, audit)).hold);
    } catch (error) { return json(res, error.statusCode || 503, { error: error.message }); }
  }
  const legalHoldReleaseMatch = url.pathname.match(/^\/api\/audit\/legal-holds\/([^/]+)\/release$/);
  if (legalHoldReleaseMatch && req.method === 'POST') {
    if (!requireRole('releaseLegalHold')) return;
    if (!usePostgres) return json(res, 503, { error: 'Legal holds require PostgreSQL' });
    try {
      const input = await body(req);
      const releaseReason = String(input.reason || '').trim();
      if (releaseReason.length < 8 || releaseReason.length > 2000) return json(res, 400, { error: 'Release reason must be 8–2000 characters' });
      const { store, workspaceId, user } = requestContext(req);
      const actor = user?.email || 'workspace-user';
      const holdId = decodeURIComponent(legalHoldReleaseMatch[1]);
      const audit = createAuditEvent(store, 'action', `Audit legal hold released: ${holdId}`, { workspaceId, eventType: 'audit.legal_hold.released', actor, holdId, releaseReason });
      const saved = await retentionRepository.releaseHoldWithAudit(workspaceId, holdId, actor, releaseReason, audit);
      return saved ? json(res, 200, saved.hold) : json(res, 404, { error: 'Active legal hold not found' });
    } catch (error) { return json(res, error.statusCode || 503, { error: error.message }); }
  }
  if (url.pathname === '/api/audit/events' && req.method === 'GET') {
    if (!requireRole('read')) return;
    if (!usePostgres) return json(res, 503, { error: 'Audit keyset browsing requires PostgreSQL' });
    try {
      const workspaceId = workspaceForRequest(req);
      const rawLimit = Number(url.searchParams.get('limit') || 250);
      if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 1000) return json(res, 400, { error: 'limit must be an integer from 1 to 1000' });
      const cursorValue = url.searchParams.get('cursor');
      const cursor = cursorValue ? auditCursor.decodeCursor(cursorValue, workspaceId, 'events') : null;
      const snapshot = cursor ? null : await auditRepository.bounds(workspaceId);
      const upperSequence = cursor?.upperSequence ?? snapshot.upperSequence;
      const requestedBefore = url.searchParams.has('beforeSequence') ? Number(url.searchParams.get('beforeSequence')) : upperSequence + 1;
      if (!cursor && (!Number.isSafeInteger(requestedBefore) || requestedBefore < 1 || requestedBefore > upperSequence + 1)) return json(res, 400, { error: 'beforeSequence is outside the audit snapshot' });
      const beforeSequence = cursor?.beforeSequence ?? requestedBefore;
      const rows = await auditRepository.pageOlder(workspaceId, beforeSequence, upperSequence, rawLimit);
      const lastSequence = rows.at(-1)?.chain_sequence ?? beforeSequence;
      const hasMore = rows.length === rawLimit && lastSequence > 1;
      const nextCursor = hasMore ? auditCursor.encodeCursor({ operation: 'events', workspaceId, beforeSequence: lastSequence, upperSequence }) : null;
      return json(res, 200, { events: rows.map(auditRepository.eventRow), page: { limit: rawLimit, beforeSequence, upperSequence, nextCursor } });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/audit/verify' && req.method === 'GET') {
    if (!requireRole('read')) return;
    if (!usePostgres) return json(res, 503, { error: 'Audit chain verification requires PostgreSQL' });
    try {
      const workspaceId = workspaceForRequest(req);
      const rawLimit = Number(url.searchParams.get('limit') || 2000);
      if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 10000) return json(res, 400, { error: 'limit must be an integer from 1 to 10000' });
      const cursorValue = url.searchParams.get('cursor');
      const cursor = cursorValue ? auditCursor.decodeCursor(cursorValue, workspaceId, 'verify') : null;
      const bounds = cursor ? { upperSequence: cursor.upperSequence, eventCount: cursor.eventCount, headHash: cursor.expectedHeadHash } : await auditRepository.bounds(workspaceId);
      const state = cursor?.state || { workspaceId, previousHash: null, headHash: null, checked: 0, startSequence: null, endSequence: null };
      const rows = await auditRepository.page(workspaceId, state.endSequence || 0, bounds.upperSequence, rawLimit);
      const checked = verifyAuditPage(state, rows);
      if (checked.failure) return json(res, 200, { ok: false, complete: true, workspaceId, ...checked.state, failure: checked.failure, expectedCount: bounds.eventCount, expectedHeadHash: bounds.headHash });
      const nextState = checked.state;
      const complete = rows.length < rawLimit || nextState.endSequence >= bounds.upperSequence;
      if (!complete) {
        const nextCursor = auditCursor.encodeCursor({ operation: 'verify', workspaceId, afterSequence: nextState.endSequence, upperSequence: bounds.upperSequence, eventCount: bounds.eventCount, expectedHeadHash: bounds.headHash, state: nextState });
        return json(res, 200, { ok: true, complete: false, workspaceId, ...nextState, expectedCount: bounds.eventCount, expectedHeadHash: bounds.headHash, nextCursor });
      }
      let failure = null;
      if (nextState.checked !== bounds.eventCount) failure = { sequence: nextState.endSequence, eventId: null, reason: `event count mismatch: checked ${nextState.checked}, expected ${bounds.eventCount}` };
      else if (nextState.headHash !== bounds.headHash) failure = { sequence: nextState.endSequence, eventId: null, reason: 'head hash mismatch' };
      return json(res, 200, { ok: !failure, complete: true, workspaceId, ...nextState, expectedCount: bounds.eventCount, expectedHeadHash: bounds.headHash, failure });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/evidence/audit.ndjson' && req.method === 'GET') {
    if (!requireRole('exportEvidence')) return;
    if (!usePostgres) return json(res, 503, { error: 'Signed audit export requires PostgreSQL' });
    const keyFile = process.env.AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_FILE;
    const keyId = process.env.AGENTGUARD_AUDIT_SIGNING_KEY_ID || '';
    if (!keyFile || !keyId) return json(res, 503, { error: 'Signed audit export is not configured', detail: 'Configure AGENTGUARD_AUDIT_SIGNING_PRIVATE_KEY_FILE and AGENTGUARD_AUDIT_SIGNING_KEY_ID.' });
    try {
      const workspaceId = workspaceForRequest(req);
      const initialBounds = await auditRepository.bounds(workspaceId);
      const fromSequence = url.searchParams.has('fromSequence') ? Number(url.searchParams.get('fromSequence')) : 1;
      const toSequence = url.searchParams.has('toSequence') ? Number(url.searchParams.get('toSequence')) : initialBounds.upperSequence;
      if (!Number.isSafeInteger(fromSequence) || !Number.isSafeInteger(toSequence) || fromSequence < 1 || toSequence < 0 || toSequence > initialBounds.upperSequence || (initialBounds.eventCount && fromSequence > toSequence)) return json(res, 400, { error: 'Invalid audit sequence range' });

      const actor = auth.session(req)?.email || 'workspace-user';
      const auditExportEvent = { id: randomUUID(), workspaceId, kind: 'action', eventType: 'evidence.audit_exported', actor, message: `Signed audit export requested for sequences ${fromSequence} through ${toSequence}`, fromSequence, toSequence, createdAt: new Date().toISOString() };
      await governanceRepository.appendEvent(auditExportEvent);
      await governanceRepository.flushAudit();
      const snapshot = await auditRepository.bounds(workspaceId);
      const effectiveTo = url.searchParams.has('toSequence') ? toSequence : snapshot.upperSequence;
      const rows = effectiveTo >= fromSequence ? await auditRepository.range(workspaceId, fromSequence, effectiveTo, 10001) : [];
      if (rows.length > 10000) return json(res, 413, { error: 'Audit export segment exceeds 10,000 events; request a smaller sequence range.' });

      const { stableStringify, verifyAuditPage } = require('./audit-integrity');
      const exportRows = rows.map(row => ({ recordType: 'event', workspaceId: row.workspace_id, chainSequence: row.chain_sequence, previousHash: row.previous_hash || null, eventHash: row.event_hash || null, event: row.payload }));
      const eventBytes = exportRows.map(row => `${stableStringify(row)}\n`).join('');
      const fileSha256 = createHash('sha256').update(eventBytes).digest('hex');
      const chainState = { workspaceId, previousHash: rows[0]?.previous_hash || null, headHash: null, checked: 0, startSequence: null, endSequence: null };
      const checked = verifyAuditPage(chainState, rows);
      if (checked.failure) return json(res, 503, { error: 'Audit chain verification failed; export was not produced', failure: checked.failure });
      const manifest = {
        format: 'agentguard-audit-ndjson-v1', workspaceId,
        firstSequence: rows[0]?.chain_sequence ?? null, lastSequence: rows.at(-1)?.chain_sequence ?? null,
        eventCount: rows.length, predecessorHash: rows[0]?.previous_hash || null, headHash: rows.at(-1)?.event_hash || null,
        fileSha256, canonicalization: 'agentguard-audit-canonical-v1', exportedAt: new Date().toISOString(), signingKeyId: keyId, signatureAlgorithm: 'Ed25519'
      };
      const privateKey = createPrivateKey(await fs.promises.readFile(path.resolve(__dirname, keyFile)));
      if (privateKey.asymmetricKeyType !== 'ed25519') return json(res, 503, { error: 'Audit signing key must be Ed25519' });
      const signature = signBytes(null, Buffer.from(stableStringify(manifest)), privateKey).toString('base64url');
      const manifestLine = `${JSON.stringify({ recordType: 'manifest', manifest, signature: { algorithm: 'Ed25519', keyId, value: signature } })}\n`;
      const filename = `agentguard-audit-${workspaceId}-${manifest.firstSequence ?? 0}-${manifest.lastSequence ?? 0}.ndjson`.replace(/[^a-zA-Z0-9_.-]/g, '_');
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Content-Disposition': `attachment; filename="${filename}"`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      res.write(manifestLine);
      for (const row of exportRows) if (!res.write(`${stableStringify(row)}\n`)) await once(res, 'drain');
      return res.end();
    } catch (error) {
      if (res.headersSent) return res.destroy(error);
      return json(res, 500, { error: 'Signed audit export failed', detail: error.message });
    }
  }
  if (url.pathname === '/api/operations/health' && req.method === 'GET') {
    if (!requireRole('read')) return;
    try {
      const store = readStore(); const workspaceId = workspaceForRequest(req);
      let audit = { status: 'unavailable', events: 0, unhashed: null, head: null };
      let execution = { awaitingApproval: 0, claimed: 0, completed: 0, failed: 0 };
      if (usePostgres) {
        const [auditRows, headRows, executionRows] = await Promise.all([
          governanceRepository.listEvents(workspaceId, 1),
          require('./storage').postgresQuery('SELECT count(*)::int AS events, count(*) FILTER (WHERE event_hash IS NULL)::int AS unhashed, max(event_hash) AS head FROM ag_audit_events WHERE workspace_id=$1', [workspaceId]),
          require('./storage').postgresQuery('SELECT state,count(*)::int AS count FROM ag_governed_actions WHERE workspace_id=$1 GROUP BY state', [workspaceId])
        ]);
        const row = headRows.rows[0] || {}; audit = { status: Number(row.unhashed || 0) === 0 ? 'healthy' : 'attention_required', events: Number(row.events || 0), unhashed: Number(row.unhashed || 0), head: row.head || null, latest: auditRows[0]?.createdAt || null };
        for (const item of executionRows.rows) { const key = item.state === 'awaiting_approval' ? 'awaitingApproval' : item.state; if (key in execution) execution[key] = item.count; }
      }
      const backupDirectory = path.join(__dirname, 'backups');
      const backups = fs.existsSync(backupDirectory) ? fs.readdirSync(backupDirectory).filter(name => name.endsWith('.json')).map(name => ({ name, modifiedAt: fs.statSync(path.join(backupDirectory, name)).mtime.toISOString() })).sort((a,b)=>b.modifiedAt.localeCompare(a.modifiedAt)) : [];
      const staleAgents = store.agents.filter(item => inWorkspace(item, workspaceId) && item.lastSeenAt && Date.now() - new Date(item.lastSeenAt).getTime() > Number(process.env.AGENTGUARD_HEARTBEAT_TIMEOUT_MS || 60000)).length;
      return json(res, 200, { workspaceId, storage: usePostgres ? 'postgres' : 'sqlite', audit, execution, staleAgents, latestBackup: backups[0] || null, backupCount: backups.length, rateLimiting: { rejections: rateLimitRejections, mode: usePostgres && process.env.AGENTGUARD_SHARED_RATE_LIMIT !== 'false' ? 'shared-postgres' : 'local-memory', configuredPerMinute: Number(process.env.AGENTGUARD_RATE_LIMIT || 240), agentPerMinute: Number(process.env.AGENTGUARD_AGENT_RATE_LIMIT || process.env.AGENTGUARD_RATE_LIMIT || 240), companyPerMinute: Number(process.env.AGENTGUARD_COMPANY_RATE_LIMIT || Number(process.env.AGENTGUARD_RATE_LIMIT || 240) * 10), workspacePerMinute: boundedRateLimit(process.env.AGENTGUARD_WORKSPACE_RATE_LIMIT, Number(process.env.AGENTGUARD_COMPANY_RATE_LIMIT || Number(process.env.AGENTGUARD_RATE_LIMIT || 240) * 10) * 10), batchAccounting: 'each telemetry envelope consumes capacity' }, generatedAt: new Date().toISOString() });
    } catch (error) { return json(res, 500, { error: 'Operations health unavailable', detail: error.message }); }
  }
  if (url.pathname === '/api/governance/uncertain-executions' && req.method === 'GET') {
    if (!requireRole('read')) return;
    if (!usePostgres) return json(res, 503, { error: 'Execution reconciliation requires PostgreSQL' });
    const workspaceId = workspaceForRequest(req);
    const executions = await governanceRepository.listUncertainGovernedActions(workspaceId, uncertainExecutionAfterMs);
    return json(res, 200, { executions: executions || [], minimumAgeMs: uncertainExecutionAfterMs });
  }
  const reconcileExecutionMatch = url.pathname.match(/^\/api\/governance\/executions\/([^/]+)\/reconcile$/);
  if (reconcileExecutionMatch && req.method === 'POST') {
    if (!requireRole('review')) return;
    if (!usePostgres) return json(res, 503, { error: 'Execution reconciliation requires PostgreSQL' });
    try {
      const input = await body(req);
      const outcome = String(input.outcome || '');
      const evidence = String(input.evidence || '').trim();
      if (!['completed', 'not_executed'].includes(outcome)) return json(res, 400, { error: 'outcome must be completed or not_executed' });
      if (evidence.length < 8 || evidence.length > 2000) return json(res, 400, { error: 'Provide 8 to 2000 characters of supporting evidence' });
      const workspaceId = workspaceForRequest(req);
      const result = await governanceRepository.reconcileGovernedAction({ workspaceId, executionId: decodeURIComponent(reconcileExecutionMatch[1]), outcome, evidence, reviewer: auth.session(req)?.email || 'reviewer', minimumAgeMs: uncertainExecutionAfterMs });
      if (result.outcome === 'not_found') return json(res, 404, { error: 'Claimed execution not found in this workspace' });
      if (result.outcome === 'too_recent') return json(res, 409, { error: 'Execution has not been claimed long enough to reconcile', ageMs: result.ageMs, minimumAgeMs: uncertainExecutionAfterMs });
      if (result.outcome !== 'reconciled') return json(res, 409, { error: 'Execution is no longer in an uncertain claimed state', state: result.state || null });
      return json(res, 200, { outcome: result.outcome, state: result.state, executionId: result.action.executionId, actionRef: result.action.actionRef, auditSequence: result.audit.chainSequence });
    } catch (error) { return json(res, error.statusCode || 400, { error: error.message }); }
  }
  if (url.pathname === '/api/dashboard' && req.method === 'GET') {
    if (!requireRole('read')) return;
    const store = readStore(); const workspaceId = workspaceForRequest(req);
    const companies = await agentRepository.listCompanies(workspaceId);
    const agents = await agentRepository.list(workspaceId);
    const dashboardEventLimit = Math.max(50, Math.min(1000, Number(process.env.AGENTGUARD_DASHBOARD_EVENT_LIMIT || 250)));
    const [policies, approvals, assessments, incidents, alerts, alertDeliveries, relationalEvents, uncertainExecutions] = await Promise.all([governanceRepository.listPolicies(workspaceId), governanceRepository.listApprovals(workspaceId), governanceRepository.listAssessments(workspaceId), governanceRepository.listIncidents(workspaceId), governanceRepository.listAlerts(workspaceId), governanceRepository.listAlertDeliveries(workspaceId), governanceRepository.listEvents(workspaceId, dashboardEventLimit), governanceRepository.listUncertainGovernedActions(workspaceId, uncertainExecutionAfterMs)]);
    const events = relationalEvents || store.events.filter(item => inWorkspace(item, workspaceId) && item.eventType !== 'heartbeat' && !/\bheartbeat\b|agent is online/i.test(item.message || '')).slice(0, dashboardEventLimit);
    const catalog = new Map();
    for (const item of [...events, ...(approvals || [])]) {
      if (!item.agentId || (!item.actionType && !item.resource)) continue;
      if (!catalog.has(item.agentId)) catalog.set(item.agentId, { agentId: item.agentId, actionTypes: new Set(), resources: new Set() });
      const entry = catalog.get(item.agentId);
      if (item.actionType) entry.actionTypes.add(item.actionType);
      if (item.resource) entry.resources.add(item.resource);
    }
    const actionCatalog = [...catalog.values()].map(item => ({ agentId: item.agentId, actionTypes: [...item.actionTypes].sort(), resources: [...item.resources].sort() }));
    const currentAlerts = alerts || (store.alerts || []).filter(item => inWorkspace(item, workspaceId));
    const latestDeliveryByAlert = new Map(); for (const delivery of alertDeliveries || []) if (!latestDeliveryByAlert.has(delivery.alertId)) latestDeliveryByAlert.set(delivery.alertId, delivery);
    return json(res, 200, { schemaVersion: store.schemaVersion, workspace: store.workspaces.find(item => item.id === workspaceId) || { id: workspaceId, name: workspaceId }, companies: publicCompanies(companies || store.companies.filter(item => inWorkspace(item, workspaceId))), agents: publicAgents(agents || store.agents.filter(item => inWorkspace(item, workspaceId))), policies: policies || store.policies.filter(item => inWorkspace(item, workspaceId)), assessments: assessments || store.assessments.filter(item => inWorkspace(item, workspaceId)), incidents: incidents || store.incidents.filter(item => inWorkspace(item, workspaceId)), alerts: currentAlerts.map(alert => ({ ...alert, delivery: latestDeliveryByAlert.get(alert.id) || null })), alertDeliveryConfigured: Boolean(alertWebhookUrl), auditSigningConfigured, approvals: approvals || store.approvals.filter(item => inWorkspace(item, workspaceId) && item.status === 'pending'), events, actionCatalog, reconciliation: usageReconciliation(events), uncertainExecutions: uncertainExecutions || [] });
  }
  if (url.pathname === '/api/evidence/export' && req.method === 'GET') {
    if (!requireRole('exportEvidence')) return;
    try {
      const store = readStore(), workspaceId = workspaceForRequest(req), now = new Date();
      const to = url.searchParams.get('to') ? new Date(url.searchParams.get('to')) : now;
      const from = url.searchParams.get('from') ? new Date(url.searchParams.get('from')) : new Date(to.getTime() - 30 * 24 * 60 * 60 * 1000);
      if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from > to) return json(res, 400, { error: 'Invalid evidence date range' });
      if (to.getTime() - from.getTime() > 366 * 24 * 60 * 60 * 1000) return json(res, 400, { error: 'Evidence range cannot exceed 366 days' });
      const inRange = item => inWorkspace(item, workspaceId) && new Date(item.createdAt || item.attemptedAt || 0) >= from && new Date(item.createdAt || item.attemptedAt || 0) <= to;
      const relational = await governanceRepository.exportEvidence(workspaceId, from.toISOString(), to.toISOString());
      const scrubAgent = ({ credentialHash, gatewayCredential, ...agent }) => ({ ...agent, connection: agent.connection ? (({ authHeader, ...connection }) => connection)(agent.connection) : agent.connection });
      const evidence = relational || { agents: store.agents.filter(item => inWorkspace(item, workspaceId)).map(scrubAgent), policies: store.policies.filter(item => inWorkspace(item, workspaceId)), approvals: store.approvals.filter(inRange), assessments: store.assessments.filter(item => inWorkspace(item, workspaceId)), incidents: store.incidents.filter(inRange), alerts: (store.alerts || []).filter(inRange), alertDeliveries: [], auditEvents: store.events.filter(inRange) };
      const generatedAt = now.toISOString(), counts = Object.fromEntries(Object.entries(evidence).map(([key, value]) => [key, value.length]));
      const manifest = { format: 'agentguard-evidence-v1', generatedAt, workspaceId, period: { from: from.toISOString(), to: to.toISOString() }, counts, auditChain: { firstPreviousHash: evidence.auditEvents[0]?.previousHash || null, lastEventHash: evidence.auditEvents.at(-1)?.eventHash || null, eventsIncluded: evidence.auditEvents.length, truncated: evidence.auditEvents.length >= 10000 } };
      const canonical = JSON.stringify({ manifest, evidence });
      const bundle = { manifest, evidence, integrity: { algorithm: 'SHA-256', contentSha256: createHash('sha256').update(canonical).digest('hex'), verification: 'Hash the compact JSON serialization of {manifest,evidence} in this file.' } };
      const actor = auth.session(req)?.email || 'workspace-user';
      await event(store, 'action', `Compliance evidence package exported for ${from.toISOString().slice(0, 10)} to ${to.toISOString().slice(0, 10)}`, { workspaceId, eventType: 'evidence.exported', actor, evidenceCounts: counts }); writeStore(store);
      const filename = `agentguard-evidence-${workspaceId}-${generatedAt.replace(/[:.]/g, '-')}.json`.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const serializedBundle = JSON.stringify(bundle, null, 2), exportDirectory = path.join(__dirname, 'exports');
      await fs.promises.mkdir(exportDirectory, { recursive: true });
      await fs.promises.writeFile(path.join(exportDirectory, filename), serializedBundle, { encoding: 'utf8', flag: 'wx' });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': `attachment; filename="${filename}"`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); return res.end(serializedBundle);
    } catch (error) { return json(res, 500, { error: 'Evidence export failed', detail: error.message }); }
  }
  const alertMatch = url.pathname.match(/^\/api\/alerts\/([^/]+)\/acknowledge$/);
  if (alertMatch && req.method === 'POST') {
    if (!requireRole('operate')) return;
    try {
      const store = structuredClone(readStore()), workspaceId = workspaceForRequest(req); const alertId = decodeURIComponent(alertMatch[1]);
      const alert = (await governanceRepository.listAlerts(workspaceId))?.find(item => item.id === alertId) || (store.alerts || []).find(item => item.id === alertId && inWorkspace(item, workspaceId));
      if (!alert) return json(res, 404, { error: 'Alert not found' });
      const user = auth.session(req); Object.assign(alert, { status: 'acknowledged', acknowledgedBy: user?.email || 'workspace-user', acknowledgedAt: new Date().toISOString() });
      const audit = createAuditEvent(store, 'action', `Alert acknowledged: ${alert.title}`, { workspaceId, agentId: alert.agentId, eventType: 'alert.acknowledged', alertId: alert.id, actor: alert.acknowledgedBy });
      if (usePostgres) {
        const saved = await governanceRepository.acknowledgeAlertWithAudit(alert, audit);
        if (saved.outcome === 'not_found') return json(res, 404, { error: 'Alert not found' });
        if (saved.outcome !== 'acknowledged') return json(res, 409, { error: 'Alert has already been acknowledged' });
        Object.assign(alert, saved.alert); store.events.unshift(saved.audit);
      } else {
        await governanceRepository.upsertAlert(alert); await event(store, 'action', audit.message, audit);
      }
      const index = (store.alerts || []).findIndex(item => item.id === alert.id && inWorkspace(item, workspaceId));
      if (index >= 0) store.alerts[index] = alert; else (store.alerts ||= []).unshift(alert);
      writeStore(store); return json(res, 200, alert);
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const alertDeliveryMatch = url.pathname.match(/^\/api\/alerts\/([^/]+)\/deliver$/);
  if (alertDeliveryMatch && req.method === 'POST') {
    if (!requireRole('operate')) return;
    try { const store = readStore(), workspaceId = workspaceForRequest(req); const alert = (await governanceRepository.listAlerts(workspaceId))?.find(item => item.id === alertDeliveryMatch[1]) || (store.alerts || []).find(item => item.id === alertDeliveryMatch[1]); if (!alert) return json(res, 404, { error: 'Alert not found' }); if (!alertWebhookUrl) return json(res, 409, { error: 'Webhook delivery is not configured' }); const delivery = await dispatchAlertDelivery(alert); const status = delivery.status === 'delivered' ? 200 : delivery.status === 'queued' ? 202 : 502; return json(res, status, delivery); } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const incidentMatch = url.pathname.match(/^\/api\/incidents\/([^/]+)$/);
  if (incidentMatch && req.method === 'PATCH') {
    if (!requireRole('operate')) return;
    try {
      const store = structuredClone(readStore()), workspaceId = workspaceForRequest(req); const incidentId = decodeURIComponent(incidentMatch[1]); const incident = (await governanceRepository.listIncidents(workspaceId))?.find(item => item.id === incidentId) || store.incidents.find(item => item.id === incidentId && inWorkspace(item, workspaceId));
      if (!incident) return json(res, 404, { error: 'Incident not found' });
      const input = await body(req); if (!['open', 'investigating', 'resolved'].includes(input.status || '')) return json(res, 400, { error: 'status must be open, investigating, or resolved' });
      const expectedUpdatedAt = incident.updatedAt; const reviewer = auth.session(req); incident.status = input.status; incident.owner = input.owner === undefined ? incident.owner : String(input.owner || '').slice(0, 160) || null; incident.updatedAt = new Date().toISOString(); incident.resolvedAt = input.status === 'resolved' ? incident.updatedAt : null; incident.timeline = [...(incident.timeline || []), { at: incident.updatedAt, actor: reviewer?.email || 'workspace-user', note: String(input.note || `Status changed to ${input.status}`).slice(0, 2000) }];
      const audit = createAuditEvent(store, 'action', `Incident ${input.status}: ${incident.title}`, { workspaceId, agentId: incident.agentId, eventType: 'incident.updated', incidentId: incident.id, actor: reviewer?.email || 'workspace-user' });
      if (usePostgres) {
        const saved = await governanceRepository.saveIncidentWithAudit(incident, audit, expectedUpdatedAt);
        if (saved.outcome === 'not_found') return json(res, 404, { error: 'Incident not found' });
        if (saved.outcome === 'stale') return json(res, 409, { error: 'Incident changed since it was loaded. Refresh and retry.' });
        store.events.unshift(saved.audit);
      } else {
        await governanceRepository.upsertIncident(incident); await event(store, 'action', audit.message, audit);
      }
      const index = store.incidents.findIndex(item => item.id === incident.id && inWorkspace(item, workspaceId)); if (index >= 0) store.incidents[index] = incident; else store.incidents.unshift(incident);
      writeStore(store);
      return json(res, 200, incident);
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const assessmentHistoryMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/assessment\/history$/);
  if (assessmentHistoryMatch && req.method === 'GET') {
    if (!requireRole('read')) return;
    if (!usePostgres) return json(res, 503, { error: 'Assessment history requires PostgreSQL' });
    return json(res, 200, await governanceRepository.listAssessmentRevisions(decodeURIComponent(assessmentHistoryMatch[1]), workspaceForRequest(req)));
  }
  const assessmentMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/assessment$/);
  if (assessmentMatch && req.method === 'GET') {
    if (!requireRole('read')) return;
    const store = readStore(); const workspaceId = workspaceForRequest(req); const assessment = (await governanceRepository.getAssessment(decodeURIComponent(assessmentMatch[1]), workspaceId)) || store.assessments.find(item => item.agentId === decodeURIComponent(assessmentMatch[1]) && inWorkspace(item, workspaceId));
    return json(res, 200, assessment || null);
  }
  if (assessmentMatch && (req.method === 'POST' || req.method === 'PATCH')) {
    if (!requireRole('configure')) return;
    try {
      const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req); const agentId = decodeURIComponent(assessmentMatch[1]);
      const registeredAgent = usePostgres ? await agentRepository.get(workspaceId, agentId) : store.agents.find(agent => agent.id === agentId && inWorkspace(agent, workspaceId));
      if (!registeredAgent) return json(res, 404, { error: 'Agent not found' });
      const input = await body(req); const now = new Date().toISOString();
      const allowedLevels = new Set(['none','low','medium','high','critical']);
      if (!['low','medium','high','critical'].includes(input.impactLevel) || !allowedLevels.has(input.privacyRisk) || !allowedLevels.has(input.biasRisk) || !allowedLevels.has(input.securityRisk) || !['strong','partial','none'].includes(input.humanOversight)) return json(res, 400, { error: 'Complete the impact, privacy, bias, security, and oversight ratings' });
      if (String(input.purpose || '').trim().length < 8 || String(input.rationale || '').trim().length < 8) return json(res, 400, { error: 'Purpose and rationale must each contain at least 8 characters' });
      const fields = ['purpose', 'intendedUse', 'prohibitedUse', 'dataTypes', 'affectedPeople', 'impactLevel', 'privacyRisk', 'biasRisk', 'securityRisk', 'humanOversight', 'mitigations', 'owner', 'reviewDueAt', 'status', 'rationale', 'evidenceReferences'];
      let assessment = await governanceRepository.getAssessment(agentId, workspaceId);
      if (assessment === undefined) assessment = store.assessments.find(item => item.agentId === agentId && inWorkspace(item, workspaceId));
      const expectedUpdatedAt = assessment?.updatedAt || null;
      if (!assessment) assessment = { id: randomUUID(), workspaceId, agentId, createdAt: now };
      for (const field of fields) if (input[field] !== undefined) assessment[field] = input[field];
      const actor = requestContext(req).user?.email || 'workspace-user';
      Object.assign(assessment, scoreRiskAssessment(registeredAgent, assessment), { reviewer: actor });
      assessment.pendingChanges = [];
      assessment.updatedAt = now; assessment.status = assessment.status || 'draft';
      const audit = createAuditEvent(store, 'action', `AI risk assessment ${expectedUpdatedAt ? 'updated' : 'created'} for ${agentId}`, { workspaceId, agentId, assessmentId: assessment.id, eventType: 'assessment.updated', metadata: { status: assessment.status, impactLevel: assessment.impactLevel || null } });
      if (usePostgres) {
        const saved = await governanceRepository.saveAssessmentWithAudit(assessment, audit, expectedUpdatedAt);
        if (saved.outcome === 'exists' || saved.outcome === 'stale') return json(res, 409, { error: 'Assessment changed since it was loaded. Refresh and retry.' });
        if (saved.outcome === 'not_found') return json(res, 404, { error: 'Assessment not found' });
        assessment = saved.assessment; store.events.unshift(saved.audit);
      } else {
        await governanceRepository.upsertAssessment(assessment); await event(store, 'action', audit.message, audit);
      }
      const index = store.assessments.findIndex(item => item.agentId === agentId && inWorkspace(item, workspaceId)); if (index >= 0) store.assessments[index] = assessment; else store.assessments.unshift(assessment);
      writeStore(store); return json(res, req.method === 'POST' ? 201 : 200, assessment);
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  if (url.pathname === '/api/agents' && req.method === 'GET') {
    if (integrationApiKey && authorizedIntegration(req)) return json(res, 200, publicAgents(readStore().agents));
    if (!requireRole('read')) return;
    const workspaceId = workspaceForRequest(req);
    return json(res, 200, publicAgents(readStore().agents.filter(item => inWorkspace(item, workspaceId))));
  }
  if (url.pathname === '/api/agents' && req.method === 'POST') {
    if (!requireRole('operate')) return;
    try {
      const input = await body(req);
      if (!input.name || !input.team || !Array.isArray(input.tools)) return json(res, 400, { error: 'name, team, and tools are required' });
      const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req);
      const companyId = String(input.companyId || '').trim().toLowerCase();
      if (!companyId) return json(res, 400, { error: 'Select or create a company before registering an agent' });
      if (!store.companies.some(company => company.id === companyId && inWorkspace(company, workspaceId))) return json(res, 404, { error: 'Unknown company' });
      if (input.parentId && !store.agents.some(parent => parent.id === input.parentId && parent.companyId === companyId && inWorkspace(parent, workspaceId))) return json(res, 400, { error: 'Parent agent must belong to the same company' });
      const credential = issueToken();
      const now = new Date().toISOString();
      const agent = { id: generateAgentId(store), workspaceId, companyId, name: input.name, agentType: input.agentType || 'general', framework: input.framework || 'unknown', model: input.model || null, version: input.version || null, team: input.team, tools: input.tools, parentId: input.parentId || null, riskTier: input.riskTier || 'unassessed', dataClass: input.dataClass || 'internal', autonomy: input.autonomy || 'assistive', status: 'registered', runtimeStatus: 'offline', createdAt: now, updatedAt: now, lastSeenAt: null, credentialHash: credential.hash, connection: input.runtimeUrl ? { mode: 'url-binding', runtimeUrl: normalizedRuntimeUrl(input.runtimeUrl), desiredState: 'stopped', state: 'stopped' } : { mode: 'gateway', desiredState: 'running', state: 'awaiting_telemetry' } };
      const audit = createAuditEvent(store, 'action', `Agent registered: ${agent.name}`, { workspaceId, agentId: agent.id, actor: 'workspace-user' });
      let committedAudit = audit;
      if (usePostgres) {
        const saved = await agentRepository.saveWithAudit(agent, audit, { create: true });
        Object.assign(agent, saved.agent); committedAudit = saved.audit;
      } else {
        store.agents.push(agent); await agentRepository.upsert(agent); await event(store, 'action', audit.message, audit);
      }
      if (usePostgres) { store.agents.push(agent); store.events.unshift(committedAudit); }
      writeStore(store);
      return json(res, 201, { ...agent, credentialHash: undefined, gatewayCredential: credential.token, gateway: { endpoint: '/api/gateway/events', companyId, agentId: agent.id, modes: ['opentelemetry', 'sidecar', 'gateway', 'sdk'] } });
    } catch (error) { return json(res, error.statusCode || (usePostgres && error.code === '23505' ? 409 : 400), { error: error.message }); }
  }
  const coverageMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/coverage$/);
  if (coverageMatch && req.method === 'GET') {
    const store = readStore();
    if (!(integrationApiKey && authorizedIntegration(req)) && !requireRole('read')) return;
    const workspaceId = workspaceForRequest(req);
    const agent = store.agents.find(item => item.id === decodeURIComponent(coverageMatch[1]) && inWorkspace(item, workspaceId));
    if (!agent) return json(res, 404, { error: 'Agent not found' });
    const policies = (await governanceRepository.listPolicies(workspaceId)) || store.policies.filter(item => inWorkspace(item, workspaceId));
    const events = (await governanceRepository.listEvents(workspaceId, 5000)) || store.events.filter(item => inWorkspace(item, workspaceId));
    return json(res, 200, { agentId: agent.id, companyId: agent.companyId, generatedAt: new Date().toISOString(), coverage: enforcementCoverage(agent, events, policies) });
  }
  if (url.pathname === '/api/agents/bulk' && req.method === 'POST') {
    if (!((integrationApiKey && authorizedIntegration(req)) || requireRole('operate'))) return;
    try {
      const input = await body(req);
      if (!Array.isArray(input.agents) || !input.agents.length) return json(res, 400, { error: 'agents must be a non-empty array' });
      if (input.agents.length > 1000) return json(res, 400, { error: 'Maximum 1000 agents per request' });
      const store = structuredClone(readStore()); const created = []; const rejected = []; const audits = []; const workspaceId = auth.session(req) ? workspaceForRequest(req) : String(input.workspaceId || process.env.AGENTGUARD_DEFAULT_WORKSPACE_ID || 'default'); const companyId = String(input.companyId || 'default');
      if (!store.companies.some(company => company.id === companyId && inWorkspace(company, workspaceId))) return json(res, 404, { error: 'Unknown company' });
      for (const item of input.agents) {
        const name = String(item.name || '').trim();
        if (!name) { rejected.push({ item, reason: 'name is required' }); continue; }
        const id = generateAgentId(store);
        const now = new Date().toISOString();
        const agent = { id, workspaceId, companyId, name, team: item.team || input.team || 'Unassigned', tools: Array.isArray(item.tools) ? item.tools : [], parentId: item.parentId || null, riskTier: item.riskTier || input.riskTier || 'unassessed', dataClass: item.dataClass || input.dataClass || 'internal', autonomy: item.autonomy || input.autonomy || 'assistive', status: 'registered', runtimeStatus: 'offline', createdAt: now, updatedAt: now, lastSeenAt: null };
        store.agents.push(agent); created.push(agent);
        audits.push(createAuditEvent(store, 'action', `Agent registered: ${agent.name}`, { workspaceId, agentId: agent.id, actor: 'workspace-user' }));
      }
      if (usePostgres) {
        const saved = await agentRepository.saveManyWithAudit(created, audits);
        for (let index = 0; index < saved.length; index++) {
          const row = saved[index];
          const agentIndex = store.agents.findIndex(agent => agent.id === row.agent.id && inWorkspace(agent, workspaceId));
          if (agentIndex >= 0) store.agents[agentIndex] = row.agent;
          store.events.unshift(row.audit);
        }
        created.splice(0, created.length, ...saved.map(row => row.agent));
      } else {
        for (let index = 0; index < created.length; index++) {
          await agentRepository.upsert(created[index]);
          await event(store, 'action', audits[index].message, audits[index]);
        }
      }
      writeStore(store); return json(res, 201, { created, rejected, count: created.length });
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const agentMatch = url.pathname.match(/^\/api\/agents\/([^/]+)$/);
  if (agentMatch && req.method === 'PATCH') {
    if (!requireRole('configure')) return;
    try {
      const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req);
      const agent = usePostgres ? await agentRepository.get(workspaceId, decodeURIComponent(agentMatch[1])) : store.agents.find(item => item.id === agentMatch[1] && inWorkspace(item, workspaceId));
      if (!agent) return json(res, 404, { error: 'Agent not found' });
      const beforeAgent = structuredClone(agent);
      const expectedUpdatedAt = agent.updatedAt;
      const input = await body(req);
      if (input.archived !== undefined) { if (typeof input.archived !== 'boolean') return json(res, 400, { error: 'archived must be boolean' }); agent.archived = input.archived; agent.status = input.archived ? 'archived' : 'registered'; }
      if (input.companyId !== undefined) {
        const companyId = String(input.companyId);
        if (!store.companies.some(company => company.id === companyId && inWorkspace(company, workspaceId))) return json(res, 404, { error: 'Unknown company' });
        agent.companyId = companyId;
      }
      for (const field of ['name', 'team', 'parentId', 'riskTier', 'dataClass', 'autonomy', 'agentType', 'framework', 'model', 'version']) if (input[field] !== undefined) agent[field] = input[field];
      if (agent.parentId) {
        const parent = store.agents.find(item => item.id === agent.parentId && inWorkspace(item, workspaceId));
        if (!parent || parent.companyId !== agent.companyId) return json(res, 400, { error: 'Parent agent must belong to the same company' });
      }
      if (input.runtimeUrl !== undefined) agent.connection = input.runtimeUrl ? { ...(agent.connection || {}), mode: 'managed-http', runtimeUrl: normalizedRuntimeUrl(input.runtimeUrl), desiredState: 'stopped', state: 'stopped', lastError: null } : null;
      if (input.tools !== undefined) { if (!Array.isArray(input.tools)) return json(res, 400, { error: 'tools must be an array' }); agent.tools = input.tools; }
      agent.updatedAt = new Date().toISOString();
      const hardFields = ['companyId','parentId','riskTier','dataClass','autonomy'];
      const softFields = ['tools','agentType','framework','model','version'];
      const hardChanges = hardFields.filter(field => JSON.stringify(beforeAgent[field] ?? null) !== JSON.stringify(agent[field] ?? null));
      const softChanges = softFields.filter(field => JSON.stringify(beforeAgent[field] ?? null) !== JSON.stringify(agent[field] ?? null));
      if ((beforeAgent.connection?.runtimeUrl || null) !== (agent.connection?.runtimeUrl || null)) softChanges.push('runtimeUrl');
      const toolDetails = softChanges.includes('tools') ? { added: (agent.tools || []).filter(tool => !(beforeAgent.tools || []).includes(tool)), removed: (beforeAgent.tools || []).filter(tool => !(agent.tools || []).includes(tool)) } : null;
      const reviewReason = hardChanges.length ? `Material governance configuration changed: ${hardChanges.join(', ')}` : null;
      const assessmentChange = softChanges.length ? { changedFields: softChanges, reason: `Operational configuration changed: ${softChanges.join(', ')}`, details: toolDetails ? { tools: toolDetails } : null } : null;
      const actor = auth.session(req)?.email || 'workspace-user';
      const changedFields = [...hardChanges, ...softChanges];
      const audit = createAuditEvent(store, 'action', input.archived === undefined ? `Agent updated: ${agent.name}` : `Agent ${input.archived ? 'archived' : 'restored'}: ${agent.name}`, { workspaceId, agentId: agent.id, actor, metadata: changedFields.length ? { assessmentReviewRequired: Boolean(reviewReason), changeTier: reviewReason ? 'hard' : 'soft', changedFields, ...(toolDetails ? { toolChanges: toolDetails } : {}) } : undefined });
      let committedAudit = audit;
      if (usePostgres) {
        const saved = await agentRepository.saveWithAudit(agent, audit, { expectedUpdatedAt, assessmentReviewReason: reviewReason, assessmentChange });
        Object.assign(agent, saved.agent); committedAudit = saved.audit;
        const index = store.agents.findIndex(item => item.id === agent.id && inWorkspace(item, workspaceId));
        if (index >= 0) store.agents[index] = agent; else store.agents.push(agent);
        store.events.unshift(committedAudit);
        if (saved.assessmentReviewAudit) store.events.unshift(saved.assessmentReviewAudit);
      } else {
        await agentRepository.upsert(agent); await event(store, 'action', audit.message, audit);
        const index = store.agents.findIndex(item => item.id === agent.id && inWorkspace(item, workspaceId));
        if (index >= 0) store.agents[index] = agent;
      }
      writeStore(store);
      return json(res, 200, agent);
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const credentialMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/credentials$/);
  if (credentialMatch && req.method === 'POST') {
    if (!requireRole('configure')) return;
    try {
      const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req); const agentId = decodeURIComponent(credentialMatch[1]);
      const agent = usePostgres ? await agentRepository.get(workspaceId, agentId) : store.agents.find(item => item.id === agentId && inWorkspace(item, workspaceId));
      if (!agent) return json(res, 404, { error: 'Agent not found' });
      const expectedUpdatedAt = agent.updatedAt; const credential = issueToken();
      agent.credentialHash = credential.hash;
      agent.connection = { ...(agent.connection || {}), mode: 'gateway', desiredState: 'running', state: 'awaiting_telemetry', lastError: null };
      agent.status = 'registered'; agent.runtimeStatus = 'offline'; agent.updatedAt = new Date().toISOString();
      const audit = createAuditEvent(store, 'action', `Gateway credential rotated: ${agent.name}`, { workspaceId, agentId: agent.id, companyId: agent.companyId, eventType: 'agent.credential_rotated', actor: 'workspace-user' });
      if (usePostgres) {
        const saved = await agentRepository.saveWithAudit(agent, audit, { expectedUpdatedAt });
        Object.assign(agent, saved.agent); store.events.unshift(saved.audit);
        const index = store.agents.findIndex(item => item.id === agent.id && inWorkspace(item, workspaceId));
        if (index >= 0) store.agents[index] = agent; else store.agents.push(agent);
      } else {
        await event(store, 'action', audit.message, audit); await agentRepository.upsert(agent);
        const index = store.agents.findIndex(item => item.id === agent.id && inWorkspace(item, workspaceId));
        if (index >= 0) store.agents[index] = agent;
      }
      writeStore(store);
      return json(res, 201, { companyId: agent.companyId, agentId: agent.id, gatewayCredential: credential.token, endpoint: '/api/gateway/events' });
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  const connectionMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/connection\/(start|stop)$/);
  if (connectionMatch && req.method === 'POST') {
    if (!requireRole('operate')) return;
    try {
    const agentId = decodeURIComponent(connectionMatch[1]);
    const action = connectionMatch[2];
    const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req);
    const agent = usePostgres ? await agentRepository.get(workspaceId, agentId) : store.agents.find(item => item.id === agentId && inWorkspace(item, workspaceId));
    if (!agent) return json(res, 404, { error: 'Agent not found' });
    if (agent.archived) return json(res, 409, { error: 'Restore this agent before connecting it' });
    const expectedUpdatedAt = agent.updatedAt;
    if (action === 'stop') {
      agent.status = 'registered';
      agent.connection = { ...(agent.connection || {}), desiredState: 'stopped', state: 'stopped', lastError: null };
      agent.updatedAt = new Date().toISOString();
      const audit = createAuditEvent(store, 'action', `Managed connector stopped: ${agent.name}`, { workspaceId, agentId, eventType: 'connector.stopped', actor: 'workspace-user' });
      if (usePostgres) {
        const saved = await agentRepository.saveWithAudit(agent, audit, { expectedUpdatedAt });
        Object.assign(agent, saved.agent); store.events.unshift(saved.audit);
      } else {
        await event(store, 'action', audit.message, audit); await agentRepository.upsert(agent);
      }
      const index = store.agents.findIndex(item => item.id === agent.id && inWorkspace(item, workspaceId));
      if (index >= 0) store.agents[index] = agent; else store.agents.push(agent);
      writeStore(store);
      return json(res, 200, agent);
    }
    try {
      const input = await body(req);
      const runtimeUrl = input.runtimeUrl || agent.connection?.runtimeUrl;
      const normalizedUrl = normalizedRuntimeUrl(runtimeUrl);
      const activeAgents = usePostgres ? await agentRepository.list(workspaceId) : store.agents;
      const owner = runtimeUrlOwner({ ...store, agents: activeAgents }, normalizedUrl, agent.id);
      if (owner) return json(res, 409, { error: `This API URL is already connected to ${owner.name} (${owner.id}). Use that agent's Stop action before rebinding it.` });
      agent.connection = { ...(agent.connection || {}), mode: 'url-binding', runtimeUrl: normalizedUrl, boundAgentId: agent.id, desiredState: 'running', state: 'connecting', lastError: null };
      agent.updatedAt = new Date().toISOString();
      const audit = createAuditEvent(store, 'action', `Managed connector start requested: ${agent.name}`, { workspaceId, agentId, eventType: 'connector.start_requested', actor: 'workspace-user' });
      if (usePostgres) {
        const saved = await agentRepository.saveWithAudit(agent, audit, { expectedUpdatedAt });
        Object.assign(agent, saved.agent); store.events.unshift(saved.audit);
      } else {
        await event(store, 'action', audit.message, audit); await agentRepository.upsert(agent);
      }
      const index = store.agents.findIndex(item => item.id === agent.id && inWorkspace(item, workspaceId));
      if (index >= 0) store.agents[index] = agent; else store.agents.push(agent);
      writeStore(store);
      return json(res, 200, await refreshManagedConnection(agentId, true));
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 502), { error: error.message }); }
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  if (url.pathname === '/api/policies' && req.method === 'POST') {
    if (!requireRole('configure')) return;
    try {
      const input = await body(req);
      if (!input.name || !input.scope || !input.agentId || !input.actionType) return json(res, 400, { error: 'name, scope, agentId, and actionType are required' });
      if (!['allow', 'require_approval', 'block'].includes(input.effect || 'require_approval')) return json(res, 400, { error: 'effect must be allow, require_approval, or block' });
      if (!Number.isInteger(Number(input.priority ?? 100))) return json(res, 400, { error: 'priority must be an integer' });
      const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req);
      if (input.agentId !== '*' && !store.agents.some(agent => agent.id === input.agentId && inWorkspace(agent, workspaceId))) return json(res, 404, { error: 'Unknown agent' });
      const now = new Date().toISOString();
      const policy = { id: randomUUID(), workspaceId, name: input.name, scope: input.scope, agentId: input.agentId, actionType: input.actionType, resourcePattern: input.resourcePattern || '*', effect: input.effect || 'require_approval', priority: Number(input.priority ?? 100), enabled: Boolean(input.enabled), ...normalizedBudget(input), version: 1, createdAt: now, updatedAt: now };
      const audit = createAuditEvent(store, 'action', `Policy created: ${policy.name}`, { workspaceId, eventType: 'policy.created', policyId: policy.id, version: policy.version, actor: 'workspace-user' });
      let committedAudit = audit, assessmentAudits = [];
      if (usePostgres) { const saved = await governanceRepository.savePolicyWithAudit(policy, audit, 0); committedAudit = saved.audit; assessmentAudits = saved.assessmentAudits || []; }
      else { await governanceRepository.upsertPolicy(policy); await event(store, 'action', audit.message, audit); }
      store.policies.push(policy);
      if (usePostgres) store.events.unshift(committedAudit, ...assessmentAudits);
      writeStore(store);
      return json(res, 201, policy);
    } catch (error) { return json(res, error.statusCode || (usePostgres && error.code === '23505' ? 409 : 400), { error: error.message }); }
  }
  if (url.pathname === '/api/policies/simulate' && req.method === 'POST') {
    if (!requireRole('read')) return;
    try {
      const input = await body(req); const store = readStore(); const workspaceId = workspaceForRequest(req);
      if (!input.agentId || !input.actionType) return json(res, 400, { error: 'agentId and actionType are required' });
      const agent = store.agents.find(item => item.id === input.agentId && inWorkspace(item, workspaceId));
      if (!agent) return json(res, 404, { error: 'Unknown agent' });
      const policies = (await governanceRepository.listPolicies(workspaceId)) || store.policies;
      const resource = actionResource(input); const permission = toolPermission(agent, input);
      if (!permission.allowed) return json(res, 200, { decision: 'block', reason: permission.tool ? `Tool “${permission.tool}” is not granted to this agent.` : 'Tool call is missing its tool name. Add an exact tool name to the agent’s grants and identify it as tool or resource tool:<name>.', permission: { tool: permission.tool, grantedTools: permission.grants || [] }, evaluated: { agentId: agent.id, actionType: input.actionType, resource } });
      const policy = matchingPolicy(policies, workspaceId, agent.id, input.actionType, resource);
      const budgetReason = policy && exceedsBudget(policy, input);
      const dailyBudget = policy ? await governanceRepository.previewDailyBudget({ workspaceId, agentId: agent.id, policy, input }) : null;
      const simulatedBudgetReason = budgetReason || dailyBudget?.reason || null;
      const explanation = policy ? `Matched ${policy.agentId === '*' ? 'workspace-wide' : 'agent-specific'} policy at priority ${policy.priority ?? 100}; ${policy.actionType} ${policy.resourcePattern || '*'} → ${policy.effect}.` : 'No enabled policy matched this agent, action type, and resource; default allow applies.';
      return json(res, 200, { decision: policy ? simulatedBudgetReason ? 'block' : policy.effect === 'require_approval' ? 'awaiting_approval' : policy.effect : 'allow', policy: policy ? { id: policy.id, name: policy.name, agentId: policy.agentId, actionType: policy.actionType, resourcePattern: policy.resourcePattern || '*', effect: policy.effect, version: policy.version, priority: policy.priority, maxTokens: policy.maxTokens || null, maxCostUsd: policy.maxCostUsd || null, dailyMaxTokens: policy.dailyMaxTokens || null, dailyMaxCostUsd: policy.dailyMaxCostUsd || null, dailyMaxActions: policy.dailyMaxActions || null } : null, dailyBudget, reason: simulatedBudgetReason || explanation, evaluated: { agentId: agent.id, actionType: input.actionType, resource, action: input.action || null, estimatedTokens: input.estimatedTokens ?? null, estimatedCostUsd: input.estimatedCostUsd ?? null } });
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
        const company = store.companies.find(item => item.id === (input.companyId || input.agent.companyId));
        store.agents.push({ ...input.agent, id: input.agentId, workspaceId: company?.workspaceId || 'default', companyId: company?.id || input.companyId || input.agent.companyId || 'default', status: 'healthy', createdAt: new Date().toISOString(), lastSeenAt: new Date().toISOString() });
      }
      const connectedAgent = store.agents.find(x => x.id === input.agentId);
      if (usePostgres) {
        const workspaceId = connectedAgent.workspaceId || 'default';
        const result = await governanceRepository.checkGovernedAction({ workspaceId, agentId: input.agentId, input, resource: actionResource(input), toolPermission, matchingPolicy, exceedsBudget, approvalTtlMs });
        if (result.outcome === 'not_found') return json(res, 404, { error: 'Unknown agent' });
        if (result.outcome === 'archived') return json(res, 409, { error: 'Agent is archived; restore it before sending activity' });
        if (alertWebhookUrl && result.alert) void dispatchAlertDelivery(result.alert);
        const status = result.decision === 'awaiting_approval' && result.approval ? 202 : 200;
        const response = { decision: result.decision };
        for (const key of ['reason', 'permission', 'approvalId', 'policyId', 'policy', 'claimRequired']) if (result[key] !== undefined) response[key] = result[key];
        return json(res, status, response);
      }
      if (connectedAgent.archived) return json(res, 409, { error: 'Agent is archived; restore it before sending activity' });
      const permission = toolPermission(connectedAgent, input);
      if (!permission.allowed) {
        const reason = permission.tool ? `Tool “${permission.tool}” is not granted to this agent.` : 'Tool call is missing its tool name.';
        await event(store, 'block', `Tool permission denied: ${reason}`, { agentId: input.agentId, eventType: 'tool.permission_denied', actionType: input.actionType, resource: input.resource || '*', actionRef: input.actionRef, tool: permission.tool, grantedTools: permission.grants || [] });
        writeStore(store);
        return json(res, 200, { decision: 'block', reason, permission: { tool: permission.tool, grantedTools: permission.grants || [] } });
      }
      connectedAgent.status = 'healthy';
      connectedAgent.lastSeenAt = new Date().toISOString();
      connectedAgent.lastActivityAt = connectedAgent.lastSeenAt;
      connectedAgent.runtimeStatus = 'running';
      connectedAgent.currentTask = { id: input.actionRef || null, name: input.action };
      await agentRepository.upsert(connectedAgent);
      const resource = actionResource(input);
      const policySource = await governanceRepository.listPolicies(connectedAgent.workspaceId || 'default');
      const policy = matchingPolicy(policySource || store.policies, connectedAgent.workspaceId || 'default', input.agentId, input.actionType, resource);
      if (!policy) {
        await event(store, 'action', `Allowed by default: ${input.action}`, { agentId: input.agentId, eventType: 'policy.allowed', actionType: input.actionType, resource, actionRef: input.actionRef, estimatedTokens: input.estimatedTokens ?? null, estimatedCostUsd: input.estimatedCostUsd ?? null });
        writeStore(store);
        return json(res, 200, { decision: 'allow' });
      }
      const budgetReason = exceedsBudget(policy, input);
      if (budgetReason) {
        await event(store, 'block', `Budget blocked by ${policy.name}: ${input.action} — ${budgetReason}`, { agentId: input.agentId, eventType: 'policy.budget_blocked', actionType: input.actionType, resource, actionRef: input.actionRef, policyId: policy.id, estimatedTokens: input.estimatedTokens ?? null, estimatedCostUsd: input.estimatedCostUsd ?? null });
        writeStore(store);
        return json(res, 200, { decision: 'block', policyId: policy.id, policy: policy.name, reason: budgetReason });
      }
      const approvalMatches = x => x.actionRef === input.actionRef && x.agentId === input.agentId && x.action === input.action && x.actionType === input.actionType && x.resource === resource && x.policyId === policy.id && x.policyVersion === policy.version;
      const existing = (await governanceRepository.findApprovalForAction({ agentId: input.agentId, actionRef: input.actionRef, action: input.action, actionType: input.actionType, resource, policyId: policy.id, policyVersion: policy.version }, connectedAgent.workspaceId || 'default')) || store.approvals.find(approvalMatches);
      if (existing?.status === 'pending' && existing.expiresAt && new Date(existing.expiresAt).getTime() <= Date.now()) {
        const expired = { status: 'denied', decision: 'expired', decidedAt: new Date().toISOString(), decidedBy: 'system', rationale: 'Approval expired before the action resumed.' };
        const updated = (await governanceRepository.decideApproval(existing.id, connectedAgent.workspaceId || 'default', expired)) || { ...existing, ...expired };
        if (!usePostgres) await governanceRepository.upsertApproval(updated);
        const index = store.approvals.findIndex(item => item.id === updated.id); if (index >= 0) store.approvals[index] = updated;
        await event(store, 'block', `Approval expired: ${updated.action}`, { agentId: updated.agentId, eventType: 'approval.expired', approvalId: updated.id, policyId: updated.policyId, actionRef: updated.actionRef });
        writeStore(store);
        return json(res, 200, { decision: 'block', approvalId: updated.id, reason: 'Approval expired; reviewer action is no longer valid' });
      } else if (existing?.status === 'approved') {
        await governanceRepository.upsertGovernedAction({ id: randomUUID(), workspaceId: connectedAgent.workspaceId || 'default', agentId: input.agentId, actionRef: input.actionRef, actionType: input.actionType, action: input.action, resource, policyId: policy.id, policyVersion: policy.version, approvalId: existing.id, state: 'approved', createdAt: existing.createdAt });
        writeStore(store);
        return json(res, 200, { decision: 'ready_to_execute', approvalId: existing.id, claimRequired: true });
      }
      if (existing?.status === 'denied') return json(res, 200, { decision: 'block', approvalId: existing.id, policy: existing.risk });
      if (policy.effect === 'block') {
        await event(store, 'block', `Blocked by ${policy.name}: ${input.action}`, { agentId: input.agentId, eventType: 'policy.blocked', actionType: input.actionType, resource, actionRef: input.actionRef, policyId: policy.id });
        writeStore(store);
        return json(res, 200, { decision: 'block', policyId: policy.id, policy: policy.name });
      }
      if (policy.effect === 'allow') {
        await event(store, 'action', `Allowed by ${policy.name}: ${input.action}`, { agentId: input.agentId, eventType: 'policy.allowed', actionType: input.actionType, resource, actionRef: input.actionRef, policyId: policy.id, estimatedTokens: input.estimatedTokens ?? null, estimatedCostUsd: input.estimatedCostUsd ?? null });
        writeStore(store);
        return json(res, 200, { decision: 'allow', policyId: policy.id });
      }
      const existingPending = existing?.status === 'pending' && (!existing.expiresAt || new Date(existing.expiresAt).getTime() > Date.now()) ? existing : store.approvals.find(x => approvalMatches(x) && x.status === 'pending' && (!x.expiresAt || new Date(x.expiresAt).getTime() > Date.now()));
      if (existingPending) {
        await governanceRepository.upsertGovernedAction({ id: randomUUID(), workspaceId: connectedAgent.workspaceId || 'default', agentId: input.agentId, actionRef: input.actionRef, actionType: input.actionType, action: input.action, resource, policyId: policy.id, policyVersion: policy.version, approvalId: existingPending.id, state: 'awaiting_approval', createdAt: existingPending.createdAt });
        return json(res, 200, { decision: 'awaiting_approval', approvalId: existingPending.id });
      }
      const approval = { id: randomUUID(), workspaceId: connectedAgent.workspaceId || 'default', companyId: connectedAgent.companyId || 'default', agentId: input.agentId, actionType: input.actionType, action: input.action, resource, risk: policy.name, actionRef: input.actionRef, policyId: policy.id, policyVersion: policy.version, status: 'pending', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + approvalTtlMs).toISOString() };
      store.approvals.push(approval);
      await governanceRepository.upsertApproval(approval);
      await governanceRepository.upsertGovernedAction({ id: randomUUID(), workspaceId: approval.workspaceId, agentId: input.agentId, actionRef: input.actionRef, actionType: input.actionType, action: input.action, resource, policyId: policy.id, policyVersion: policy.version, approvalId: approval.id, state: 'awaiting_approval', createdAt: approval.createdAt });
      await event(store, 'approval', `Approval required by ${policy.name}: ${approval.action}`, { agentId: input.agentId, eventType: 'approval.required', actionType: input.actionType, resource, actionRef: input.actionRef, approvalId: approval.id, policyId: policy.id, estimatedTokens: input.estimatedTokens ?? null, estimatedCostUsd: input.estimatedCostUsd ?? null });
      writeStore(store);
      return json(res, 202, { decision: 'awaiting_approval', approvalId: approval.id });
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  if (url.pathname === '/api/guard/executions/claim' && req.method === 'POST') {
    try {
      if (!usePostgres) return json(res, 503, { error: 'Durable governed execution requires PostgreSQL' });
      const input = await body(req);
      if (!input.agentId || !input.actionRef || !input.actionType || !input.action) return json(res, 400, { error: 'agentId, actionRef, actionType, and action are required' });
      const store = readStore();
      const agent = store.agents.find(item => item.id === input.agentId);
      if (!agent) return json(res, 404, { error: 'Unknown agent' });
      const permission = toolPermission(agent, input);
      if (!permission.allowed) {
        const reason = permission.tool ? `Tool “${permission.tool}” is not granted to this agent.` : 'Tool call is missing its tool name.';
        await event(store, 'block', `Tool permission denied at execution claim: ${reason}`, { agentId: input.agentId, eventType: 'tool.permission_denied', actionType: input.actionType, resource: input.resource || '*', actionRef: input.actionRef, tool: permission.tool, grantedTools: permission.grants || [] });
        writeStore(store);
        return json(res, 403, { decision: 'block', reason });
      }
      const result = await governanceRepository.claimGovernedAction({ workspaceId: agent.workspaceId || 'default', agentId: input.agentId, actionRef: input.actionRef, actionType: input.actionType, action: input.action, resource: actionResource(input), executionId: randomUUID(), auditId: randomUUID() });
      if (result.outcome === 'claimed') return json(res, 200, { decision: 'execute', executionId: result.action.executionId, approvalId: result.action.approvalId });
      if (result.outcome === 'duplicate') return json(res, 409, { decision: 'duplicate_suppressed', executionId: result.action.executionId, state: result.action.state });
      if (result.outcome === 'mismatch') return json(res, 409, { decision: 'block', reason: 'Action details do not match the approved request' });
      if (result.outcome === 'denied') return json(res, 403, { decision: 'block', reason: 'Approval was denied' });
      if (result.outcome === 'not_approved') return json(res, 409, { decision: 'awaiting_approval', approvalId: result.action?.approvalId || null });
      return json(res, 404, { error: 'Governed action not found; call /api/guard/check first' });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/guard/executions/complete' && req.method === 'POST') {
    try {
      if (!usePostgres) return json(res, 503, { error: 'Durable governed execution requires PostgreSQL' });
      const input = await body(req);
      if (!input.agentId || !input.executionId) return json(res, 400, { error: 'agentId and executionId are required' });
      const agent = readStore().agents.find(item => item.id === input.agentId);
      if (!agent) return json(res, 404, { error: 'Unknown agent' });
      const result = await governanceRepository.completeGovernedAction({ workspaceId: agent.workspaceId || 'default', agentId: input.agentId, executionId: input.executionId, success: input.success !== false, result: input.result || null, error: input.error || null, auditId: randomUUID() });
      if (result.outcome === 'completed' || result.outcome === 'failed') return json(res, 200, { state: result.outcome, executionId: input.executionId });
      if (result.outcome === 'duplicate') return json(res, 200, { state: result.action.state, executionId: input.executionId, duplicate: true });
      if (result.outcome === 'invalid_state') return json(res, 409, { error: 'Execution is not currently claimed' });
      return json(res, 404, { error: 'Execution not found' });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  const approvalStatusMatch = url.pathname.match(/^\/api\/approvals\/([^/]+)$/);
  if (approvalStatusMatch && req.method === 'GET') {
    const store = readStore(); const workspaceId = workspaceForRequest(req);
    const approval = (await governanceRepository.getApproval(approvalStatusMatch[1], workspaceId)) || store.approvals.find(x => x.id === approvalStatusMatch[1] && inWorkspace(x, workspaceId));
    if (!approval) return json(res, 404, { error: 'Approval not found' });
    return json(res, 200, { id: approval.id, status: approval.status, decision: approval.decision || null });
  }
  if (url.pathname === '/api/approvals' && req.method === 'POST') {
    if (!requireRole('operate')) return;
    try {
      const input = await body(req);
      if (!input.agentId || !input.action || !input.risk) return json(res, 400, { error: 'agentId, action, and risk are required' });
      const store = structuredClone(readStore()); const workspaceId = workspaceForRequest(req);
      const registeredAgent = usePostgres ? await agentRepository.get(workspaceId, input.agentId) : store.agents.find(agent => agent.id === input.agentId && inWorkspace(agent, workspaceId));
      if (!registeredAgent) return json(res, 404, { error: 'Unknown agent' });
      const approval = { id: randomUUID(), workspaceId, agentId: input.agentId, action: input.action, risk: input.risk, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + approvalTtlMs).toISOString() };
      approval.status = 'pending';
      let savedApproval = approval;
      if (usePostgres) {
        const message = `Approval requested: ${approval.action}`;
        const audit = createAuditEvent(store, 'approval', message, { agentId: input.agentId, eventType: 'approval.required', approvalId: approval.id, actor: 'workspace-user' });
        const saved = await governanceRepository.createApprovalWithAudit(approval, audit);
        savedApproval = saved.approval; store.events.unshift(saved.audit);
        if (alertWebhookUrl && saved.alert) void dispatchAlertDelivery(saved.alert).catch(error => console.error('Approval notification delivery failed:', error.message));
      } else {
        await governanceRepository.upsertApproval(approval);
        await event(store, 'approval', `Approval requested: ${approval.action}`, { agentId: input.agentId, eventType: 'approval.required', approvalId: approval.id, actor: 'workspace-user' });
      }
      store.approvals.push(savedApproval); writeStore(store);
      return json(res, 201, savedApproval);
    } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }
  }
  if ((url.pathname === '/api/agent-events' || url.pathname === '/api/v1/events') && req.method === 'POST') {
    try {
      const input = await body(req);
      const eventType = input.event || input.eventType;
      const message = input.message || `${eventType || 'agent.event'} received from agent ${input.agentId || 'unknown'}`;
      if (!input.agentId || !eventType) return json(res, 400, { error: 'agentId and eventType are required' });
      if (usePostgres) {
        try {
          const identity = { agentId: input.agentId, companyId: input.companyId || null, workspaceId: input.workspaceId || null };
          const credential = { integration: authorizedIntegration(req) };
          const agent = await telemetryRepository.readAgent(identity, credential);
          const envelope = normalizeEnvelope({ ...input, eventType, message, companyId: agent.companyId,
            task: input.task || (input.taskId ? { id: input.taskId, name: message } : null),
            metadata: { ...(input.metadata || {}), resource: input.resource || null, durationMs: input.durationMs || null } });
          const result = await telemetryRepository.ingest({ ...identity, workspaceId: agent.workspaceId, companyId: agent.companyId }, [envelope], credential);
          publishTelemetry(result);
          return json(res, 201, { ok: true, duplicate: Boolean(result.duplicates) });
        } catch (error) { return telemetryError(res, error); }
      }
      const store = readStore();
      if (!store.agents.some(x => x.id === input.agentId)) {
        if (!input.agent || !input.agent.name || !input.agent.team || !Array.isArray(input.agent.tools)) return json(res, 404, { error: 'Unknown agent; include agent metadata to register it' });
        const company = store.companies.find(item => item.id === (input.companyId || input.agent.companyId));
        store.agents.push({ id: input.agentId, workspaceId: company?.workspaceId || 'default', companyId: company?.id || input.companyId || 'default', name: input.agent.name, team: input.agent.team, tools: input.agent.tools, status: 'healthy', createdAt: new Date().toISOString(), lastSeenAt: new Date().toISOString() });
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
      await agentRepository.upsert(connectedAgent);
      if (eventType !== 'heartbeat') {
        const kind = ['failed', 'tool.blocked', 'policy.blocked'].includes(eventType) || eventType.endsWith('.failed') ? 'block' : eventType.includes('approval') ? 'approval' : 'action';
        event(store, kind, message, { agentId: input.agentId, eventType, actionRef: input.actionRef || null, runId: input.runId || null, taskId: input.taskId || null, tool: input.tool || null, resource: input.resource || null, eventStatus: input.status || null, durationMs: input.durationMs || null, sourceTimestamp: input.timestamp || null, metadata: input.metadata || null });
      }
      await governanceRepository.flushAudit(); writeStore(store);
      return json(res, 201, { ok: true });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (url.pathname === '/api/policies/' && req.method === 'PATCH') return json(res, 404, { error: 'Missing policy id' });
  const policyMatch = url.pathname.match(/^\/api\/policies\/([^/]+)$/);
  const approvalMatch = url.pathname.match(/^\/api\/approvals\/([^/]+)\/(approve|deny)$/);
  try {
    if (policyMatch && req.method === 'PATCH') {
      if (!requireRole('configure')) return;
      const store = structuredClone(readStore()), workspaceId = workspaceForRequest(req);
      const policy = (await governanceRepository.getPolicy(policyMatch[1], workspaceId)) || store.policies.find(x => x.id === policyMatch[1] && inWorkspace(x, workspaceId));
      if (!policy) return json(res, 404, { error: 'Policy not found' });
      const expectedVersion = Number(policy.version || 1);
      const input = await body(req);
      if (input.enabled !== undefined && typeof input.enabled !== 'boolean') return json(res, 400, { error: 'enabled must be boolean' });
      if (input.enabled !== undefined) policy.enabled = input.enabled;
      for (const field of ['name', 'scope', 'agentId', 'actionType', 'resourcePattern', 'effect', 'priority', 'maxTokens', 'maxCostUsd', 'dailyMaxTokens', 'dailyMaxCostUsd', 'dailyMaxActions']) {
        if (input[field] === undefined) continue;
        if (field === 'effect' && !['allow', 'require_approval', 'block'].includes(input[field])) return json(res, 400, { error: 'Invalid policy effect' });
        if (field === 'priority' && !Number.isInteger(Number(input[field]))) return json(res, 400, { error: 'priority must be an integer' });
        if (field === 'agentId' && input[field] !== '*' && !store.agents.some(agent => agent.id === input[field] && inWorkspace(agent, workspaceId))) return json(res, 404, { error: 'Unknown agent' });
        if (['maxTokens', 'maxCostUsd', 'dailyMaxTokens', 'dailyMaxCostUsd', 'dailyMaxActions'].includes(field)) Object.assign(policy, normalizedBudget({ ...policy, [field]: input[field] }));
        else policy[field] = field === 'priority' ? Number(input[field]) : input[field];
      }
      policy.version = (policy.version || 1) + 1;
      policy.updatedAt = new Date().toISOString();
      const audit = createAuditEvent(store, 'action', `Policy updated: ${policy.name} (version ${policy.version})`, { workspaceId, eventType: 'policy.updated', policyId: policy.id, version: policy.version, actor: 'workspace-user' });
      let committedAudit = audit, assessmentAudits = [];
      if (usePostgres) { const saved = await governanceRepository.savePolicyWithAudit(policy, audit, expectedVersion); committedAudit = saved.audit; assessmentAudits = saved.assessmentAudits || []; }
      else await governanceRepository.upsertPolicy(policy);
      const mirrorIndex = store.policies.findIndex(item => item.id === policy.id && inWorkspace(item, workspaceId));
      if (mirrorIndex >= 0) store.policies[mirrorIndex] = policy;
      else store.policies.push(policy);
      if (usePostgres) store.events.unshift(committedAudit, ...assessmentAudits);
      else await event(store, 'action', audit.message, audit);
      writeStore(store); return json(res, 200, policy);
    }
    if (approvalMatch && req.method === 'POST') {
      if (!requireRole('review')) return;
      const store = readStore(), workspaceId = workspaceForRequest(req), currentApproval = (await governanceRepository.getApproval(approvalMatch[1], workspaceId)) || store.approvals.find(x => x.id === approvalMatch[1] && inWorkspace(x, workspaceId));
      if (!currentApproval || (!usePostgres && currentApproval.status !== 'pending')) return json(res, 404, { error: 'Pending approval not found' });
      const decisionInput = await body(req);
      const agent = store.agents.find(x => x.id === currentApproval.agentId);
      const decision = approvalMatch[2];
      if (usePostgres) {
        const reviewer = auth.session(req);
        const update = { status: decision === 'approve' ? 'approved' : 'denied', decision, decidedAt: new Date().toISOString(), decidedBy: reviewer?.email || 'workspace-user', rationale: String(decisionInput.rationale || '').slice(0, 2000), agentName: agent?.name || currentApproval.agentId };
        const result = await governanceRepository.decideApprovalWithAudit(currentApproval.id, workspaceId, update);
        if (result.outcome === 'not_found') return json(res, 404, { error: 'Approval not found' });
        if (result.outcome === 'already_decided') return json(res, 409, { error: 'Approval has already been decided' });
        const approval = result.approval;
        if (alertWebhookUrl && result.alert) void dispatchAlertDelivery(result.alert);
        if (result.outcome === 'expired') return json(res, 409, { error: 'Approval has expired', decision: 'expired' });
        return json(res, 200, { decision, approvalId: approval.id });
      }
      if (currentApproval.expiresAt && new Date(currentApproval.expiresAt).getTime() <= Date.now()) {
        const expired = { status: 'denied', decision: 'expired', decidedAt: new Date().toISOString(), decidedBy: 'system', rationale: 'Approval expired before a reviewer decided.' };
        const updated = (await governanceRepository.decideApproval(currentApproval.id, workspaceId, expired)) || null;
        if (updated) {
          if (!usePostgres) await governanceRepository.upsertApproval(updated);
          await event(store, 'block', `Approval expired: ${updated.action}`, { agentId: updated.agentId, eventType: 'approval.expired', approvalId: updated.id, actionRef: updated.actionRef, policyId: updated.policyId });
          writeStore(store);
        }
        return json(res, 409, { error: 'Approval has expired', decision: 'expired' });
      }
      const reviewer = auth.session(req);
      const update = { status: decision === 'approve' ? 'approved' : 'denied', decision, decidedAt: new Date().toISOString(), decidedBy: reviewer?.email || 'workspace-user', rationale: String(decisionInput.rationale || '').slice(0, 2000) };
      const approval = (await governanceRepository.decideApproval(currentApproval.id, workspaceId, update)) || (!usePostgres ? { ...currentApproval, ...update } : null);
      if (!approval) return json(res, 409, { error: 'Approval has already been decided' });
      if (!usePostgres) await governanceRepository.upsertApproval(approval);
      const mirrorIndex = store.approvals.findIndex(item => item.id === approval.id && inWorkspace(item, workspaceId));
      if (mirrorIndex >= 0) store.approvals[mirrorIndex] = approval; else store.approvals.push(approval);
      await event(store, decision === 'approve' ? 'action' : 'block', `${agent?.name || approval.agentId} was ${decision === 'approve' ? 'approved to' : 'denied permission to'} ${approval.action.toLowerCase()}.${approval.rationale ? ' Note: ' + approval.rationale : ''}`, { agentId: approval.agentId, eventType: decision === 'approve' ? 'approval.approved' : 'approval.denied', actionRef: approval.actionRef, approvalId: approval.id, policyId: approval.policyId, decidedBy: approval.decidedBy, rationale: approval.rationale });
      writeStore(store); return json(res, 200, { decision, approvalId: approval.id });
    }
  } catch (error) { return json(res, error.statusCode || (usePostgres && /^[0-9A-Z]{5}$/.test(error.code || '') ? 503 : 400), { error: error.message }); }

  const requested = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  const file = path.resolve(dist, requested);
  if (!file.startsWith(dist + path.sep) && file !== path.join(dist, 'index.html')) return json(res, 403, { error: 'Forbidden' });
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return json(res, 404, { error: 'Not found' });
  const extension = path.extname(file).toLowerCase();
  const type = ({ '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon' })[extension] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': type }); fs.createReadStream(file).pipe(res);
});
if (require.main === module) {
  validateProductionConfig();
  initializeStore().then(() => {
    const poller = setInterval(async () => {
      const store = readStore();
      if (usePostgres && alertWebhookUrl) await drainAlertOutbox();
      try {
        const expiredApprovals = await governanceRepository.expireDueApprovals();
        for (const approval of expiredApprovals) {
          const index = store.approvals.findIndex(item => item.id === approval.id && inWorkspace(item, approval.workspaceId));
          if (index >= 0) store.approvals[index] = approval;
          if (alertWebhookUrl && approval.alert) void dispatchAlertDelivery(approval.alert);
        }
        if (expiredApprovals.length) writeStore(store);
      } catch (error) { console.error('Approval expiry sweep failed:', error.message); }
      try {
        const approvalReminders = await governanceRepository.createDueApprovalReminders(Number(process.env.AGENTGUARD_APPROVAL_REMINDER_MINUTES || 5));
        if (approvalReminders.length) {
          for (const item of approvalReminders) { store.events.unshift(item.audit); store.alerts.unshift(item.alert); if (alertWebhookUrl) void dispatchAlertDelivery(item.alert); }
          writeStore(store);
        }
      } catch (error) { console.error('Approval reminder sweep failed:', error.message); }
      try {
        const dueReviews = await governanceRepository.createDueAssessmentReviewAlerts();
        if (dueReviews.length) {
          for (const item of dueReviews) { store.events.unshift(item.audit); store.incidents.unshift(item.incident); store.alerts.unshift(item.alert); }
          writeStore(store);
        }
      } catch (error) { console.error('Assessment review sweep failed:', error.message); }
      try {
        const upcomingReviews = await governanceRepository.createUpcomingAssessmentReviewAlerts(Number(process.env.AGENTGUARD_ASSESSMENT_REMINDER_DAYS || 7));
        if (upcomingReviews.length) {
          for (const item of upcomingReviews) { store.events.unshift(item.audit); store.alerts.unshift(item.alert); }
          writeStore(store);
        }
      } catch (error) { console.error('Upcoming assessment review sweep failed:', error.message); }
      for (const agent of store.agents.filter(item => item.connection?.mode === 'url-binding' && item.connection?.desiredState === 'running')) refreshManagedConnection(agent.id).catch(() => {});
      if (usePostgres) {
        try {
          const results = await telemetryRepository.expireStates(Number(process.env.AGENTGUARD_HEARTBEAT_TIMEOUT_MS || 60_000), Number(process.env.AGENTGUARD_IDLE_TIMEOUT_MS || 60_000));
          for (const result of results) publishTelemetry(result);
        } catch (error) { console.error('Runtime expiry could not be committed:', error.message); }
        return;
      }
      const heartbeatChanges = expireHeartbeats(store, Number(process.env.AGENTGUARD_HEARTBEAT_TIMEOUT_MS || 60_000));
      const activityChanges = expireRuntimeActivity(store, Number(process.env.AGENTGUARD_IDLE_TIMEOUT_MS || 60_000));
      if (heartbeatChanges || activityChanges) {
        await Promise.all(store.agents.map(agent => agentRepository.upsert(agent).catch(() => null)));
        writeStore(store);
      }
    }, managedPollMs);
    poller.unref();
    server.listen(port, () => console.log(`AgentGuard running at http://localhost:${port}`));
  }).catch(error => { console.error('Storage initialization failed:', error); process.exitCode = 1; });
}
module.exports = { server, normalizedRuntimeUrl, probeManagedAgent, runtimeUrlOwner };
