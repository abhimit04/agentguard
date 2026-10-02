const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHmac, randomUUID } = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { Client, Pool } = require('pg');
const execFileAsync = promisify(execFile);
const relationalSchema = fs.readFileSync(path.join(__dirname, '..', 'infra', 'postgres', '002-relational.sql'), 'utf8');

async function prepareRelationalFixture(connectionString) {
  const client = new Client({ connectionString });
  try {
    await client.connect();
    await client.query(relationalSchema);
    await client.query(`INSERT INTO ag_workspaces(id,name) VALUES ('test','Governed execution test') ON CONFLICT DO NOTHING`);
  } finally { await client.end(); }
}

const sourceUrl = new URL(process.env.DATABASE_URL || '');
if (!sourceUrl.hostname) throw new Error('DATABASE_URL is required');
const databaseName = `agentguard_governed_test_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
const adminUrl = new URL(sourceUrl); adminUrl.pathname = '/postgres';
const testUrl = new URL(sourceUrl); testUrl.pathname = `/${databaseName}`;
const admin = new Client({ connectionString: adminUrl.toString() });

async function run() {
  if (process.argv.includes('--restart-probe')) {
    const storage = require('../storage');
    await storage.initializeStore();
    const { server } = require('../server');
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const base = `http://127.0.0.1:${server.address().port}`;
      const sessionPayload = Buffer.from(JSON.stringify({ email: 'reviewer@example.test', name: 'Test Reviewer', createdAt: Date.now(), purpose: 'session' })).toString('base64url');
      const sessionCookie = `agentguard_session=${sessionPayload}.${createHmac('sha256', process.env.JWT_SECRET).update(sessionPayload).digest('base64url')}`;
      const claim = async (actionRef, action = 'Transfer funds') => fetch(`${base}/api/guard/executions/claim`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env.AGENTGUARD_API_KEY}` }, body: JSON.stringify({ agentId: 'workflow-agent', actionRef, actionType: 'tool.call', action, tool: 'payments', resource: 'tool:payments' }) });
      const duplicate = await claim('workflow-action');
      assert.equal(duplicate.status, 409);
      assert.equal((await duplicate.json()).decision, 'duplicate_suppressed', 'a fresh server process must not re-grant a completed action');
      const uncertain = await claim('crash-action', 'Submit irreversible payment');
      assert.equal(uncertain.status, 409);
      assert.equal((await uncertain.json()).decision, 'duplicate_suppressed', 'a fresh server process must not repeat an action whose external outcome is uncertain');
      const persisted = await storage.postgresQuery(`SELECT state,payload->'result'->>'receipt' AS receipt FROM ag_governed_actions WHERE workspace_id='test' AND action_ref='workflow-action'`);
      assert.deepEqual(persisted.rows[0], { state: 'completed', receipt: 'workflow-receipt' }, 'governed action and result must survive an actual server-process restart');
      const uncertainState = await storage.postgresQuery(`SELECT state FROM ag_governed_actions WHERE workspace_id='test' AND action_ref='crash-action'`);
      assert.equal(uncertainState.rows[0].state, 'claimed', 'crash recovery remains explicitly uncertain instead of silently re-executing');
      const effects = await storage.postgresQuery(`SELECT count(*)::int AS n FROM test_downstream_effects WHERE action_ref='crash-action'`);
      assert.equal(effects.rows[0].n, 1, 'idempotent fake downstream side effect remains single across restart');
      const execution = await storage.postgresQuery(`SELECT execution_id FROM ag_governed_actions WHERE workspace_id='test' AND action_ref='crash-action'`);
      const dashboard = await fetch(`${base}/api/dashboard`, { headers: { cookie: sessionCookie } });
      const dashboardBody = await dashboard.json();
      assert.ok(dashboardBody.uncertainExecutions.some(item => item.actionRef === 'crash-action'), 'stale claimed execution appears for reviewer reconciliation');
      const reconciled = await fetch(`${base}/api/governance/executions/${encodeURIComponent(execution.rows[0].execution_id)}/reconcile`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: sessionCookie }, body: JSON.stringify({ outcome: 'completed', evidence: 'Downstream idempotency ledger confirms receipt crash-receipt' }) });
      assert.equal(reconciled.status, 200, await reconciled.clone().text());
      const reconciliationResponse = await reconciled.json();
      assert.equal(reconciliationResponse.state, 'completed');
      const notExecuted = await storage.postgresQuery(`SELECT execution_id FROM ag_governed_actions WHERE workspace_id='test' AND action_ref='not-executed-action'`);
      const markedNotExecuted = await fetch(`${base}/api/governance/executions/${encodeURIComponent(notExecuted.rows[0].execution_id)}/reconcile`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: sessionCookie }, body: JSON.stringify({ outcome: 'not_executed', evidence: 'Provider lookup confirms no payment with this idempotency key' }) });
      assert.equal(markedNotExecuted.status, 200, await markedNotExecuted.clone().text());
      assert.equal((await markedNotExecuted.json()).state, 'failed');
      const evidence = await storage.postgresQuery(`SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND event_type IN ('approval.required','approval.approved','approval.denied','approval.expired','execution.claimed','execution.completed')`);
      assert.ok(evidence.rows[0].n >= 10, 'governance evidence must remain available after the server restart');
      const audit = await storage.postgresQuery(`SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND event_type='execution.reconciled'`);
      assert.equal(audit.rows[0].n, 2, 'both reconciliation outcomes must append durable audit evidence');
      const notExecutedState = await storage.postgresQuery(`SELECT state,payload->'reconciliation'->>'outcome' AS decision FROM ag_governed_actions WHERE workspace_id='test' AND action_ref='not-executed-action'`);
      assert.deepEqual(notExecutedState.rows[0], { state: 'failed', decision: 'not_executed' });
    } finally {
      await new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); });
      await storage.closePostgres();
    }
    console.log('Fresh AgentGuard server process: persisted result loaded and duplicate execution refused.');
    return;
  }
  await admin.connect();
  await admin.query(`CREATE DATABASE "${databaseName}"`);
  await prepareRelationalFixture(testUrl.toString());
  process.env.DATABASE_URL = testUrl.toString();
  process.env.AGENTGUARD_STORAGE = 'postgres';
  const storage = require('../storage');
  const repository = require('../repositories/governance');
  let appServer, runtimeServer;
  try {
    await storage.initializeStore();
    await storage.postgresQuery(`INSERT INTO ag_workspaces(id,name) VALUES ('test','Governed execution test') ON CONFLICT DO NOTHING`);
    await storage.postgresQuery(`INSERT INTO ag_memberships(id,workspace_id,email,display_name,role) VALUES ('reviewer-1','test','reviewer@example.test','Test Reviewer','reviewer') ON CONFLICT (workspace_id,email) DO UPDATE SET role='reviewer'`);
    await storage.postgresQuery(`INSERT INTO ag_memberships(id,workspace_id,email,display_name,role) VALUES ('owner-1','test','owner@example.test','Test Owner','owner') ON CONFLICT (workspace_id,email) DO UPDATE SET role='owner'`);
    await storage.postgresQuery(`INSERT INTO ag_companies(workspace_id,id,name,payload) VALUES ('test','company-1','Test company','{}') ON CONFLICT DO NOTHING`);
    const policyWriteId = `policy-write-${randomUUID()}`;
    const policyWrite = { id: policyWriteId, workspaceId: 'test', name: 'Atomic policy write', agentId: 'workflow-agent', actionType: 'tool.call', resourcePattern: 'tool:atomic-test', effect: 'require_approval', enabled: true, priority: 100, version: 1, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    const policyAudit = (id, workspaceId, eventType, version) => ({ id, workspaceId, kind: 'action', eventType, actor: 'postgres-test', message: `Policy version ${version}`, policyId: policyWriteId, version, createdAt: new Date().toISOString() });
    await assert.rejects(repository.savePolicyWithAudit(policyWrite, policyAudit(randomUUID(), 'missing-test-workspace', 'policy.test.rollback', 1), 0), /foreign key/i, 'audit insert failure must abort its policy write transaction');
    const rolledBackPolicy = await storage.postgresQuery('SELECT id FROM ag_policies WHERE workspace_id=$1 AND id=$2', ['test', policyWriteId]);
    assert.equal(rolledBackPolicy.rowCount, 0, 'policy changes must not persist when their audit append fails');
    const createdPolicy = await repository.savePolicyWithAudit(policyWrite, policyAudit(randomUUID(), 'test', 'policy.created', 1), 0);
    assert.match(createdPolicy.audit.eventHash, /^[a-f0-9]{64}$/);
    await assert.rejects(repository.savePolicyWithAudit(policyWrite, policyAudit(randomUUID(), 'test', 'policy.created', 1), 0), error => error.statusCode === 409, 'a duplicate create must conflict');
    const updatedPolicy = { ...policyWrite, name: 'Atomic policy write updated', version: 2, updatedAt: new Date().toISOString() };
    await repository.savePolicyWithAudit(updatedPolicy, policyAudit(randomUUID(), 'test', 'policy.updated', 2), 1);
    await assert.rejects(repository.savePolicyWithAudit({ ...updatedPolicy, version: 3 }, policyAudit(randomUUID(), 'test', 'policy.updated', 3), 1), error => error.statusCode === 409, 'a stale policy edit must conflict instead of overwriting a newer version');
    const policyState = await storage.postgresQuery('SELECT version,payload->>\'name\' AS name FROM ag_policies WHERE workspace_id=$1 AND id=$2', ['test', policyWriteId]);
    const policyEvidence = await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id=$1 AND payload->>\'policyId\'=$2', ['test', policyWriteId]);
    assert.deepEqual(policyState.rows[0], { version: 2, name: 'Atomic policy write updated' }, 'the committed policy version is the latest one');
    assert.equal(policyEvidence.rows[0].n, 2, 'only the committed create and update have audit evidence');
    const agentRepository = require('../repositories/agents');
    const registeredAgentId = `atomic-agent-${randomUUID()}`;
    const registeredAgent = { id: registeredAgentId, workspaceId: 'test', companyId: 'company-1', name: 'Atomic registration agent', team: 'integration-test', tools: ['test-tool'], status: 'registered', runtimeStatus: 'offline', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    const agentAudit = (workspaceId, message) => ({ id: randomUUID(), workspaceId, agentId: registeredAgentId, kind: 'action', eventType: 'agent.registered', actor: 'postgres-test', message, createdAt: new Date().toISOString() });
    await assert.rejects(agentRepository.saveWithAudit(registeredAgent, agentAudit('missing-test-workspace', 'rollback test'), { create: true }), /foreign key/i, 'audit append failure must roll back the agent insert');
    const rolledBackAgent = await storage.postgresQuery('SELECT id FROM ag_agents WHERE workspace_id=$1 AND id=$2', ['test', registeredAgentId]);
    assert.equal(rolledBackAgent.rowCount, 0, 'failed agent registration must not persist');
    const savedAgent = await agentRepository.saveWithAudit(registeredAgent, agentAudit('test', 'agent registered'), { create: true });
    assert.match(savedAgent.audit.eventHash, /^[a-f0-9]{64}$/);
    await assert.rejects(agentRepository.saveWithAudit(registeredAgent, agentAudit('test', 'duplicate registration'), { create: true }), error => error.statusCode === 409, 'duplicate agent IDs must conflict');
    const updatedAgent = { ...savedAgent.agent, name: 'Atomic registration agent updated', updatedAt: new Date(Date.now() + 1000).toISOString() };
    await agentRepository.saveWithAudit(updatedAgent, agentAudit('test', 'agent updated'), { expectedUpdatedAt: savedAgent.agent.updatedAt });
    await assert.rejects(agentRepository.saveWithAudit({ ...updatedAgent, name: 'stale overwrite' }, agentAudit('test', 'stale edit'), { expectedUpdatedAt: savedAgent.agent.updatedAt }), error => error.statusCode === 409, 'stale edits must not overwrite a newer agent version');
    const agentState = await storage.postgresQuery('SELECT name,payload->>\'name\' AS payload_name FROM ag_agents WHERE workspace_id=$1 AND id=$2', ['test', registeredAgentId]);
    const agentEvidence = await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id=$1 AND agent_id=$2', ['test', registeredAgentId]);
    assert.deepEqual(agentState.rows[0], { name: 'Atomic registration agent updated', payload_name: 'Atomic registration agent updated' }, 'agent row and payload retain the committed edit');
    assert.equal(agentEvidence.rows[0].n, 2, 'only committed registration and edit have audit evidence');
    const agent = { id: 'workflow-agent', workspaceId: 'test', companyId: 'company-1', name: 'Workflow agent', team: 'test', status: 'registered', tools: ['payments'] };
    await storage.postgresQuery(`INSERT INTO ag_agents(workspace_id,id,company_id,name,team,status,payload) VALUES ('test',$1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET payload=EXCLUDED.payload`, [agent.id, agent.companyId, agent.name, agent.team, agent.status, JSON.stringify(agent)]);
    const policy = { id: 'approval-policy', workspaceId: 'test', name: 'Payments require review', effect: 'require_approval', enabled: true, version: 1, priority: 100, agentId: agent.id, actionType: 'tool.call', resourcePattern: 'tool:payments' };
    await storage.postgresQuery(`INSERT INTO ag_policies(workspace_id,id,agent_id,name,effect,enabled,version,priority,payload) VALUES ('test',$1,$2,$3,$4,true,1,100,$5::jsonb) ON CONFLICT (workspace_id,id) DO UPDATE SET payload=EXCLUDED.payload`, [policy.id, agent.id, policy.name, policy.effect, JSON.stringify(policy)]);
    await storage.initializeStore(); // Refresh the app cache after seeding fixtures.
    await storage.postgresQuery(`CREATE OR REPLACE FUNCTION test_deny_compatibility_record_writes() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'compatibility mirror writes are disabled in the PostgreSQL runtime workflow'; END $$`);
    await storage.postgresQuery("DO $$ BEGIN IF to_regclass('public.agentguard_records') IS NOT NULL THEN CREATE TRIGGER test_deny_compatibility_record_writes BEFORE INSERT OR UPDATE OR DELETE ON agentguard_records FOR EACH ROW EXECUTE FUNCTION test_deny_compatibility_record_writes(); END IF; END $$");

    async function create(actionRef, status = 'approved', decision = status) {
      const approvalId = randomUUID();
      const now = new Date().toISOString();
      await repository.upsertApproval({ id: approvalId, workspaceId: 'test', agentId: 'agent-1', policyId: 'policy-1', status, action: 'Transfer funds', actionRef, actionType: 'tool.call', resource: 'tool:payments', policyVersion: 1, createdAt: now, decidedAt: status === 'pending' ? null : now, decision });
      await repository.upsertGovernedAction({ id: randomUUID(), workspaceId: 'test', agentId: 'agent-1', actionRef, actionType: 'tool.call', action: 'Transfer funds', resource: 'tool:payments', policyId: 'policy-1', policyVersion: 1, approvalId, state: status === 'approved' ? 'approved' : status === 'denied' ? 'denied' : 'awaiting_approval', createdAt: now });
      return approvalId;
    }

    const workflowInput = { actionRef: 'workflow-action', actionType: 'tool.call', action: 'Transfer funds', resource: 'tool:payments', tool: 'payments' };
    const checkOptions = {
      workspaceId: 'test', agentId: agent.id, input: workflowInput, resource: 'tool:payments', approvalTtlMs: 60_000,
      toolPermission: () => ({ allowed: true, tool: 'payments', grants: ['payments'] }),
      matchingPolicy: (policies, workspaceId, agentId, actionType, resource) => policies.find(item => item.enabled && item.workspaceId === workspaceId && item.agentId === agentId && item.actionType === actionType && item.resourcePattern === resource),
      exceedsBudget: () => null,
    };
    process.env.AGENTGUARD_API_KEY = randomUUID() + randomUUID();
    process.env.AGENTGUARD_REQUIRE_AUTH = 'true';
    process.env.NODE_ENV = 'test';
    process.env.AGENTGUARD_DEFAULT_WORKSPACE_ID = 'test';
    process.env.AGENTGUARD_EXECUTION_UNCERTAIN_AFTER_MS = '60000';
    process.env.JWT_SECRET = randomUUID() + randomUUID();
    const sessionPayload = Buffer.from(JSON.stringify({ email: 'reviewer@example.test', name: 'Test Reviewer', createdAt: Date.now(), purpose: 'session' })).toString('base64url');
    const sessionSignature = createHmac('sha256', process.env.JWT_SECRET).update(sessionPayload).digest('base64url');
    const reviewerCookie = `agentguard_session=${sessionPayload}.${sessionSignature}`;
    const ownerPayload = Buffer.from(JSON.stringify({ email: 'owner@example.test', name: 'Test Owner', createdAt: Date.now(), purpose: 'session' })).toString('base64url');
    const ownerCookie = `agentguard_session=${ownerPayload}.${createHmac('sha256', process.env.JWT_SECRET).update(ownerPayload).digest('base64url')}`;
    appServer = require('../server').server;
    await new Promise(resolve => appServer.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${appServer.address().port}`;
    const post = (route, payload, headers = {}) => fetch(`${base}${route}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(payload) });
    const registeredResponse = await post('/api/agents', { name: 'API registration test', team: 'integration-test', companyId: 'company-1', agentType: 'research', framework: 'LangGraph', model: 'governed-model-v1', version: '1.0.0', riskTier: 'medium', dataClass: 'confidential', autonomy: 'supervised', tools: ['test-tool'] }, { cookie: ownerCookie });
    assert.equal(registeredResponse.status, 201, await registeredResponse.clone().text());
    const registeredBody = await registeredResponse.json();
    assert.equal(registeredBody.credentialHash, undefined, 'registration response must not disclose credential hashes');
    assert.match(registeredBody.id, /^\d{4}$/);
    assert.deepEqual({ agentType: registeredBody.agentType, framework: registeredBody.framework, model: registeredBody.model, version: registeredBody.version, riskTier: registeredBody.riskTier, dataClass: registeredBody.dataClass, autonomy: registeredBody.autonomy }, { agentType: 'research', framework: 'LangGraph', model: 'governed-model-v1', version: '1.0.0', riskTier: 'medium', dataClass: 'confidential', autonomy: 'supervised' }, 'registration preserves the full governance profile');
    const editedResponse = await fetch(`${base}/api/agents/${registeredBody.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ name: 'API registration test edited' }) });
    assert.equal(editedResponse.status, 200, await editedResponse.clone().text());
    assert.equal((await editedResponse.json()).name, 'API registration test edited');
    const registeredAudit = await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id=$1 AND agent_id=$2 AND event_type IS NULL', ['test', registeredBody.id]);
    assert.equal(registeredAudit.rows[0].n, 2, 'API registration and edit each append an audit record');
    const integrationHeaders = { authorization: `Bearer ${process.env.AGENTGUARD_API_KEY}` };
    const governanceIncidentId = `atomic-incident-${randomUUID()}`;
    const governanceAlertId = `atomic-alert-${randomUUID()}`;
    const governanceIncident = { id: governanceIncidentId, workspaceId: 'test', agentId: registeredBody.id, status: 'open', severity: 'medium', title: 'Atomic incident test', owner: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), timeline: [] };
    const governanceAlert = { id: governanceAlertId, workspaceId: 'test', agentId: registeredBody.id, status: 'open', severity: 'medium', title: 'Atomic alert test', createdAt: new Date().toISOString(), channels: ['in-app'] };
    await repository.upsertIncident(governanceIncident); await repository.upsertAlert(governanceAlert);
    await storage.postgresQuery(`CREATE OR REPLACE FUNCTION test_reject_agentguard_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.message LIKE '%rollback sentinel%' OR NEW.event_type IN ('agent.credential_rotated','connector.stopped','connector.start_requested','company.credential_rotated','company.gateway_credential_rotated','workspace.member.role_updated','workspace.member.removed','assessment.updated','incident.updated','alert.acknowledged','approval.required','alert.webhook_delivered','test.signal.rollback') THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`);
    await storage.postgresQuery('CREATE TRIGGER test_reject_agentguard_audit BEFORE INSERT ON ag_audit_events FOR EACH ROW EXECUTE FUNCTION test_reject_agentguard_audit()');
    const assessmentFailure = await post(`/api/agents/${registeredBody.id}/assessment`, { purpose: 'Rollback test', rationale: 'Injected audit failure', impactLevel: 'low', privacyRisk: 'low', biasRisk: 'low', securityRisk: 'low', humanOversight: 'strong' }, { cookie: ownerCookie });
    assert.equal(assessmentFailure.status, 503, await assessmentFailure.clone().text());
    assert.equal((await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_assessments WHERE workspace_id=$1 AND agent_id=$2', ['test', registeredBody.id])).rows[0].n, 0, 'assessment write rolls back when its audit append fails');
    const failedApprovalAction = `Manual approval rollback sentinel ${randomUUID()}`;
    const failedApproval = await post('/api/approvals', { agentId: registeredBody.id, action: failedApprovalAction, risk: 'medium' }, { cookie: ownerCookie });
    assert.equal(failedApproval.status, 503, await failedApproval.clone().text());
    assert.equal((await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_approvals WHERE workspace_id=$1 AND agent_id=$2 AND action=$3', ['test', registeredBody.id, failedApprovalAction])).rows[0].n, 0, 'manual approval creation rolls back when its audit append fails');
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_alerts WHERE workspace_id='test' AND payload->>'action'=$1 AND payload->>'notificationType'='approval.required'", [failedApprovalAction])).rows[0].n, 0, 'failed approval transaction leaves no orphan reviewer notification');
    const incidentFailure = await fetch(`${base}/api/incidents/${governanceIncidentId}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ status: 'investigating', note: 'Failure injection' }) });
    assert.equal(incidentFailure.status, 503, await incidentFailure.clone().text());
    assert.equal((await storage.postgresQuery('SELECT status FROM ag_incidents WHERE workspace_id=$1 AND id=$2', ['test', governanceIncidentId])).rows[0].status, 'open', 'incident state rolls back when its audit append fails');
    const alertFailure = await post(`/api/alerts/${governanceAlertId}/acknowledge`, {}, { cookie: ownerCookie });
    assert.equal(alertFailure.status, 503, await alertFailure.clone().text());
    assert.equal((await storage.postgresQuery('SELECT status FROM ag_alerts WHERE workspace_id=$1 AND id=$2', ['test', governanceAlertId])).rows[0].status, 'open', 'alert remains open when its acknowledgement audit append fails');
    const failedSignalId = randomUUID();
    await assert.rejects(repository.recordGovernanceSignal({ id: failedSignalId, workspaceId: 'test', agentId: registeredBody.id, kind: 'block', eventType: 'test.signal.rollback', actor: 'postgres-test', message: 'Atomic signal rollback', createdAt: new Date().toISOString() }), /injected audit failure/);
    const failedSignalState = await storage.postgresQuery('SELECT (SELECT count(*)::int FROM ag_audit_events WHERE workspace_id=$1 AND id=$2) AS events,(SELECT count(*)::int FROM ag_incidents WHERE workspace_id=$1 AND source_event_id=$2) AS incidents,(SELECT count(*)::int FROM ag_alerts WHERE workspace_id=$1 AND title LIKE $3) AS alerts', ['test', failedSignalId, '%Atomic signal rollback%']);
    assert.deepEqual(failedSignalState.rows[0], { events: 0, incidents: 0, alerts: 0 }, 'governance signal, incident, and alert roll back together');
    const memberEmail = `atomic-member-${randomUUID()}@example.test`;
    const addMemberResponse = await post('/api/workspace/members', { email: memberEmail, role: 'viewer', name: 'Atomic membership test' }, { cookie: ownerCookie });
    assert.equal(addMemberResponse.status, 201, await addMemberResponse.clone().text());
    const memberBody = await addMemberResponse.json();
    const memberAuditAfterAdd = await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND event_type='workspace.member.added' AND message LIKE $1", [`%${memberEmail}%`]);
    assert.equal(memberAuditAfterAdd.rows[0].n, 1, 'membership creation commits with an audit event');
    // Verify bulk registration commits its complete batch and audit evidence together.
    const failedCompanyId = `rollback-${randomUUID().slice(0, 8)}`;
    const failedCompany = await post('/api/companies', { id: failedCompanyId, name: 'rollback sentinel company' }, { cookie: ownerCookie });
    assert.equal(failedCompany.status, 503, await failedCompany.clone().text());
    assert.equal((await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_companies WHERE workspace_id=$1 AND id=$2', ['test', failedCompanyId])).rows[0].n, 0, 'failed manual company audit append rolls back company creation');
    const failedProvisionId = `gateway-rollback-${randomUUID().slice(0, 8)}`;
    const failedProvision = await post('/api/gateway/companies/register', { workspaceId: 'test', companyId: failedProvisionId, companyName: 'rollback sentinel provision company' }, integrationHeaders);
    assert.equal(failedProvision.status, 503, await failedProvision.clone().text());
    assert.equal((await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_companies WHERE workspace_id=$1 AND id=$2', ['test', failedProvisionId])).rows[0].n, 0, 'failed gateway provisioning audit append rolls back company creation');
    const memberRoleFailure = await fetch(`${base}/api/workspace/members/${memberBody.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ role: 'operator' }) });
    assert.equal(memberRoleFailure.status, 503, await memberRoleFailure.clone().text());
    assert.equal((await storage.postgresQuery('SELECT role FROM ag_memberships WHERE workspace_id=$1 AND id=$2', ['test', memberBody.id])).rows[0].role, 'viewer', 'failed role-change audit append rolls the membership update back');
    const memberDeleteFailure = await fetch(`${base}/api/workspace/members/${memberBody.id}`, { method: 'DELETE', headers: { cookie: ownerCookie } });
    assert.equal(memberDeleteFailure.status, 503, await memberDeleteFailure.clone().text());
    assert.equal((await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_memberships WHERE workspace_id=$1 AND id=$2', ['test', memberBody.id])).rows[0].n, 1, 'failed removal audit append restores membership row');
    const companyResponse = await post('/api/companies', { name: `Atomic company ${randomUUID()}` }, { cookie: ownerCookie });
    assert.equal(companyResponse.status, 201, await companyResponse.clone().text());
    const companyBody = await companyResponse.json();
    const companyCredentialBefore = await storage.postgresQuery('SELECT gateway_credential_hash FROM ag_companies WHERE workspace_id=$1 AND id=$2', ['test', companyBody.id]);
    const companyRotateFailure = await post(`/api/companies/${companyBody.id}/gateway-credentials`, {}, { cookie: ownerCookie });
    assert.equal(companyRotateFailure.status, 503, await companyRotateFailure.clone().text());
    const companyCredentialAfterFailure = await storage.postgresQuery('SELECT gateway_credential_hash FROM ag_companies WHERE workspace_id=$1 AND id=$2', ['test', companyBody.id]);
    assert.equal(companyCredentialAfterFailure.rows[0].gateway_credential_hash, companyCredentialBefore.rows[0].gateway_credential_hash, 'failed company credential rotation preserves the current credential');
    const gatewayCompanyOkId = `gateway-provision-${randomUUID().slice(0, 8)}`;
    const provisioned = await post('/api/gateway/companies/register', { workspaceId: 'test', companyId: gatewayCompanyOkId, companyName: 'Gateway provision success' }, integrationHeaders);
    assert.equal(provisioned.status, 201, await provisioned.clone().text());
    const provisionedBody = await provisioned.json();
    const provisionCredentialBefore = await storage.postgresQuery('SELECT gateway_credential_hash FROM ag_companies WHERE workspace_id=$1 AND id=$2', ['test', gatewayCompanyOkId]);
    const provisionRotateFailure = await post('/api/gateway/companies/register', { workspaceId: 'test', companyId: gatewayCompanyOkId, companyName: 'Gateway provision rollback sentinel' }, integrationHeaders);
    assert.equal(provisionRotateFailure.status, 503, await provisionRotateFailure.clone().text());
    const provisionCredentialAfterFailure = await storage.postgresQuery('SELECT name,gateway_credential_hash FROM ag_companies WHERE workspace_id=$1 AND id=$2', ['test', gatewayCompanyOkId]);
    assert.equal(provisionCredentialAfterFailure.rows[0].name, 'Gateway provision success');
    assert.equal(provisionCredentialAfterFailure.rows[0].gateway_credential_hash, provisionCredentialBefore.rows[0].gateway_credential_hash, 'failed gateway provisioning update rolls back both company and credential changes');
    const credentialBefore = await storage.postgresQuery('SELECT credential_hash FROM ag_agents WHERE workspace_id=$1 AND id=$2', ['test', registeredBody.id]);
    const rotateFailure = await post(`/api/agents/${registeredBody.id}/credentials`, {}, { cookie: ownerCookie });
    assert.equal(rotateFailure.status, 503, await rotateFailure.clone().text());
    const credentialAfterFailure = await storage.postgresQuery('SELECT credential_hash FROM ag_agents WHERE workspace_id=$1 AND id=$2', ['test', registeredBody.id]);
    assert.equal(credentialAfterFailure.rows[0].credential_hash, credentialBefore.rows[0].credential_hash, 'failed credential rotation leaves the prior credential valid');
    const stopBefore = await storage.postgresQuery("SELECT payload->'connection' AS connection FROM ag_agents WHERE workspace_id=$1 AND id=$2", ['test', registeredBody.id]);
    const stopFailure = await post(`/api/agents/${registeredBody.id}/connection/stop`, {}, { cookie: ownerCookie });
    assert.equal(stopFailure.status, 503, await stopFailure.clone().text());
    const stopAfterFailure = await storage.postgresQuery("SELECT payload->'connection' AS connection FROM ag_agents WHERE workspace_id=$1 AND id=$2", ['test', registeredBody.id]);
    assert.deepEqual(stopAfterFailure.rows[0].connection, stopBefore.rows[0].connection, 'failed stop audit append does not change connection state');
    const startFailure = await post(`/api/agents/${registeredBody.id}/connection/start`, { runtimeUrl: 'http://localhost:1/health' }, { cookie: ownerCookie });
    assert.equal(startFailure.status, 503, await startFailure.clone().text());
    const startAfterFailure = await storage.postgresQuery("SELECT payload->'connection' AS connection FROM ag_agents WHERE workspace_id=$1 AND id=$2", ['test', registeredBody.id]);
    assert.deepEqual(startAfterFailure.rows[0].connection, stopBefore.rows[0].connection, 'failed start audit append does not change connection state');
    const bulkRollbackNames = [`Bulk rollback first ${randomUUID()}`, 'Bulk rollback sentinel'];
    const bulkRollback = await post('/api/agents/bulk', { companyId: 'company-1', agents: bulkRollbackNames.map(name => ({ name })) }, { cookie: ownerCookie });
    assert.equal(bulkRollback.status, 503, await bulkRollback.clone().text());
    const bulkRollbackRows = await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_agents WHERE workspace_id=$1 AND company_id=$2 AND name=ANY($3::text[])', ['test', 'company-1', bulkRollbackNames]);
    assert.equal(bulkRollbackRows.rows[0].n, 0, 'failed bulk audit append rolls back every agent in the batch');
    await repository.enqueueAlertDelivery(governanceAlert);
    const firstOutboxClaim = await repository.claimAlertDeliveries({ workspaceId: 'test', alertId: governanceAlertId, limit: 1 });
    assert.equal(firstOutboxClaim.length, 1); assert.equal(firstOutboxClaim[0].attempts, 1);
    const rejectedDelivery = { id: randomUUID(), workspaceId: 'test', alertId: governanceAlertId, channel: 'webhook', status: 'delivered', attemptedAt: new Date().toISOString(), deliveredAt: new Date().toISOString(), httpStatus: 200 };
    const rejectedDeliveryAudit = { id: randomUUID(), workspaceId: 'test', agentId: registeredBody.id, kind: 'action', eventType: 'alert.webhook_delivered', actor: 'postgres-test', message: 'Webhook result rollback test', createdAt: new Date().toISOString(), alertId: governanceAlertId, deliveryId: rejectedDelivery.id };
    await assert.rejects(repository.finishAlertDelivery(firstOutboxClaim[0], rejectedDelivery, rejectedDeliveryAudit), /injected audit failure/);
    const rejectedDeliveryState = await storage.postgresQuery('SELECT (SELECT status FROM ag_alert_outbox WHERE workspace_id=$1 AND alert_id=$2 AND channel=$3) AS status,(SELECT count(*)::int FROM ag_alert_deliveries WHERE workspace_id=$1 AND alert_id=$2) AS attempts,(SELECT count(*)::int FROM ag_audit_events WHERE workspace_id=$1 AND id=$4) AS audit', ['test', governanceAlertId, 'webhook', rejectedDeliveryAudit.id]);
    assert.deepEqual(rejectedDeliveryState.rows[0], { status: 'in_flight', attempts: 0, audit: 0 }, 'failed delivery-result audit leaves the durable outbox lease intact and writes no partial history');
    await storage.postgresQuery('DROP TRIGGER test_reject_agentguard_audit ON ag_audit_events');
    await storage.postgresQuery("UPDATE ag_alert_outbox SET locked_until=now()-interval '1 second' WHERE workspace_id='test' AND alert_id=$1", [governanceAlertId]);
    const retryClaim = (await repository.claimAlertDeliveries({ workspaceId: 'test', alertId: governanceAlertId, limit: 1 }))[0];
    assert.equal(retryClaim.attempts, 2, 'expired delivery lease is recoverable');
    const failedDelivery = { id: randomUUID(), workspaceId: 'test', alertId: governanceAlertId, channel: 'webhook', status: 'failed', attemptedAt: new Date().toISOString(), errorMessage: 'temporary outage' };
    const failedDeliveryAudit = { id: randomUUID(), workspaceId: 'test', agentId: registeredBody.id, kind: 'block', eventType: 'alert.webhook_failed', actor: 'postgres-test', message: 'Webhook temporary failure', createdAt: new Date().toISOString(), alertId: governanceAlertId, deliveryId: failedDelivery.id };
    const retryScheduled = await repository.finishAlertDelivery(retryClaim, failedDelivery, failedDeliveryAudit, { retryDelayMs: 0 });
    assert.equal(retryScheduled.outcome, 'queued');
    const deliveryRetryClaim = (await repository.claimAlertDeliveries({ workspaceId: 'test', alertId: governanceAlertId, limit: 1 }))[0];
    assert.equal(deliveryRetryClaim.attempts, 3, 'transient delivery failures can be retried');
    const delivered = { id: randomUUID(), workspaceId: 'test', alertId: governanceAlertId, channel: 'webhook', status: 'delivered', attemptedAt: new Date().toISOString(), deliveredAt: new Date().toISOString(), httpStatus: 200 };
    const deliveredAudit = { id: randomUUID(), workspaceId: 'test', agentId: registeredBody.id, kind: 'action', eventType: 'alert.webhook_delivered', actor: 'postgres-test', message: 'Webhook delivered after retry', createdAt: new Date().toISOString(), alertId: governanceAlertId, deliveryId: delivered.id };
    assert.equal((await repository.finishAlertDelivery(deliveryRetryClaim, delivered, deliveredAudit)).outcome, 'delivered');
    const outboxFinalState = await storage.postgresQuery('SELECT (SELECT status FROM ag_alert_outbox WHERE workspace_id=$1 AND alert_id=$2 AND channel=$3) AS status,(SELECT count(*)::int FROM ag_alert_deliveries WHERE workspace_id=$1 AND alert_id=$2) AS attempts,(SELECT count(*)::int FROM ag_audit_events WHERE workspace_id=$1 AND payload->>\'alertId\'=$2 AND event_type IN (\'alert.webhook_failed\',\'alert.webhook_delivered\')) AS evidence', ['test', governanceAlertId, 'webhook']);
    assert.deepEqual(outboxFinalState.rows[0], { status: 'delivered', attempts: 2, evidence: 2 }, 'failed and successful webhook attempts retain atomic delivery history and audit evidence');
    const signalId = randomUUID();
    const signal = await repository.recordGovernanceSignal({ id: signalId, workspaceId: 'test', agentId: registeredBody.id, kind: 'block', eventType: 'test.signal.committed', actor: 'postgres-test', message: 'Atomic signal committed', createdAt: new Date().toISOString() }, 'high');
    assert.match(signal.audit.eventHash, /^[a-f0-9]{64}$/);
    const committedSignalState = await storage.postgresQuery('SELECT (SELECT count(*)::int FROM ag_audit_events WHERE workspace_id=$1 AND id=$2) AS events,(SELECT count(*)::int FROM ag_incidents WHERE workspace_id=$1 AND source_event_id=$2) AS incidents,(SELECT count(*)::int FROM ag_alerts WHERE workspace_id=$1 AND incident_id=$3) AS alerts', ['test', signalId, signal.incident.id]);
    assert.deepEqual(committedSignalState.rows[0], { events: 1, incidents: 1, alerts: 1 }, 'governance signal, incident, and alert commit together');
    const assessmentSuccess = await post(`/api/agents/${registeredBody.id}/assessment`, { purpose: 'Integration test use', rationale: 'Approved integration test scope', impactLevel: 'low', privacyRisk: 'low', biasRisk: 'low', securityRisk: 'low', humanOversight: 'strong' }, { cookie: ownerCookie });
    assert.equal(assessmentSuccess.status, 201, await assessmentSuccess.clone().text());
    const assessmentBody = await assessmentSuccess.json();
    assert.equal(assessmentBody.version, 1);
    assert.equal(assessmentBody.scoringModel, 'agentguard-risk-v1');
    assert.ok(Number.isInteger(assessmentBody.score));
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_assessment_revisions WHERE workspace_id='test' AND assessment_id=$1", [assessmentBody.id])).rows[0].n, 1, 'assessment revision is immutable and durable');
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND payload->>'assessmentId'=$1 AND event_type='assessment.updated'", [assessmentBody.id])).rows[0].n, 1, 'successful assessment write has matching audit evidence');
    const assessmentRevision = await fetch(`${base}/api/agents/${registeredBody.id}/assessment`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ ...assessmentBody, rationale: 'Second documented review', impactLevel: 'medium', status: 'approved', reviewDueAt: '2020-01-01' }) });
    assert.equal(assessmentRevision.status, 200, await assessmentRevision.clone().text());
    assert.equal((await assessmentRevision.json()).version, 2);
    const historyResponse = await fetch(`${base}/api/agents/${registeredBody.id}/assessment/history`, { headers: { cookie: ownerCookie } });
    assert.equal(historyResponse.status, 200);
    assert.deepEqual((await historyResponse.json()).map(item => item.version), [2, 1]);
    const dueReviews = await repository.createDueAssessmentReviewAlerts();
    assert.equal(dueReviews.length, 1);
    assert.equal(dueReviews[0].alert.notificationType, 'assessment.review_due');
    assert.equal((await repository.createDueAssessmentReviewAlerts()).length, 0, 'review reminder is emitted once per assessment version');
    const reviewEvidence = await storage.postgresQuery("SELECT (SELECT count(*)::int FROM ag_audit_events WHERE workspace_id='test' AND event_type='assessment.review_due') AS audit,(SELECT count(*)::int FROM ag_incidents WHERE workspace_id='test' AND source_event_id=$1) AS incidents,(SELECT count(*)::int FROM ag_alerts WHERE workspace_id='test' AND payload->>'notificationType'='assessment.review_due') AS alerts", [dueReviews[0].audit.id]);
    assert.deepEqual(reviewEvidence.rows[0], { audit: 1, incidents: 1, alerts: 1 });
    const materialEdit = await fetch(`${base}/api/agents/${registeredBody.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ riskTier: 'high' }) });
    assert.equal(materialEdit.status, 200, await materialEdit.clone().text());
    const reviewRequired = await storage.postgresQuery("SELECT status,payload->>'reviewRequiredReason' AS reason,(SELECT count(*)::int FROM ag_assessment_revisions WHERE workspace_id='test' AND assessment_id=$2) AS revisions,(SELECT count(*)::int FROM ag_audit_events WHERE workspace_id='test' AND agent_id=$1 AND event_type='assessment.review_required') AS audit FROM ag_assessments WHERE workspace_id='test' AND agent_id=$1", [registeredBody.id, assessmentBody.id]);
    assert.equal(reviewRequired.rows[0].status, 'review_required');
    assert.match(reviewRequired.rows[0].reason, /riskTier/);
    assert.equal(reviewRequired.rows[0].revisions, 2, 'system review flag does not rewrite immutable reviewer revisions');
    assert.equal(reviewRequired.rows[0].audit, 1);
    const upcomingReviewAt = new Date(Date.now() + (3 * 24 * 60 * 60 * 1000)).toISOString();
    const reassessment = await fetch(`${base}/api/agents/${registeredBody.id}/assessment`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ ...assessmentBody, rationale: 'Approved after material configuration review', impactLevel: 'high', status: 'approved', reviewDueAt: upcomingReviewAt }) });
    assert.equal(reassessment.status, 200, await reassessment.clone().text());
    assert.equal((await reassessment.json()).version, 3);
    const upcomingReviews = await repository.createUpcomingAssessmentReviewAlerts(7);
    assert.equal(upcomingReviews.length, 1);
    assert.equal(upcomingReviews[0].alert.notificationType, 'assessment.review_upcoming');
    assert.equal(upcomingReviews[0].alert.incidentId, null, 'advance reminder does not create an incident');
    assert.equal((await repository.createUpcomingAssessmentReviewAlerts(7)).length, 0, 'advance reminder is emitted once per assessment version');
    const upcomingEvidence = await storage.postgresQuery("SELECT (SELECT count(*)::int FROM ag_audit_events WHERE workspace_id='test' AND event_type='assessment.review_upcoming' AND payload->>'assessmentId'=$1) AS audit,(SELECT count(*)::int FROM ag_alerts WHERE workspace_id='test' AND payload->>'notificationType'='assessment.review_upcoming' AND payload->>'assessmentId'=$1) AS alerts,(SELECT count(*)::int FROM ag_alert_outbox o JOIN ag_alerts a ON a.workspace_id=o.workspace_id AND a.id=o.alert_id WHERE o.workspace_id='test' AND a.payload->>'notificationType'='assessment.review_upcoming' AND a.payload->>'assessmentId'=$1) AS outbox", [assessmentBody.id]);
    assert.deepEqual(upcomingEvidence.rows[0], { audit: 1, alerts: 1, outbox: 1 }, 'advance reminder, evidence, and durable delivery commit together');
    const modelEdit = await fetch(`${base}/api/agents/${registeredBody.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ framework: 'LangGraph', model: 'governed-model-v2', version: '2.0.0' }) });
    assert.equal(modelEdit.status, 200, await modelEdit.clone().text());
    const modelChangeRecorded = await storage.postgresQuery("SELECT status,jsonb_array_length(COALESCE(payload->'pendingChanges','[]'::jsonb)) AS pending_changes,payload->'pendingChanges'->0->>'reason' AS reason,(SELECT count(*)::int FROM ag_assessment_revisions WHERE workspace_id='test' AND assessment_id=$2) AS revisions,(SELECT count(*)::int FROM ag_audit_events WHERE workspace_id='test' AND agent_id=$1 AND event_type='assessment.change_recorded') AS audit FROM ag_assessments WHERE workspace_id='test' AND agent_id=$1", [registeredBody.id, assessmentBody.id]);
    assert.equal(modelChangeRecorded.rows[0].status, 'approved', 'soft changes do not invalidate an approved assessment');
    assert.equal(modelChangeRecorded.rows[0].pending_changes, 1);
    assert.match(modelChangeRecorded.rows[0].reason, /model, version/);
    assert.equal(modelChangeRecorded.rows[0].revisions, 3, 'soft changes preserve approved assessment revisions');
    assert.equal(modelChangeRecorded.rows[0].audit, 1, 'soft change has separate audit evidence');
    const toolEdit = await fetch(`${base}/api/agents/${registeredBody.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ tools: ['test-tool', 'read-only-market-data'] }) });
    assert.equal(toolEdit.status, 200, await toolEdit.clone().text());
    const toolChangeRecorded = await storage.postgresQuery("SELECT status,jsonb_array_length(payload->'pendingChanges') AS pending_changes,payload->'pendingChanges'->1->'details'->'tools' AS tool_delta,(SELECT count(*)::int FROM ag_audit_events WHERE workspace_id='test' AND agent_id=$1 AND event_type='assessment.change_recorded') AS audit FROM ag_assessments WHERE workspace_id='test' AND agent_id=$1", [registeredBody.id]);
    assert.equal(toolChangeRecorded.rows[0].status, 'approved');
    assert.equal(toolChangeRecorded.rows[0].pending_changes, 2);
    assert.deepEqual(toolChangeRecorded.rows[0].tool_delta, { added: ['read-only-market-data'], removed: [] }, 'tool changes retain added and removed identities');
    assert.equal(toolChangeRecorded.rows[0].audit, 2);
    const approvalAction = `Manual approval transaction ${randomUUID()}`;
    const approvalSuccess = await post('/api/approvals', { agentId: registeredBody.id, action: approvalAction, risk: 'medium' }, { cookie: ownerCookie });
    assert.equal(approvalSuccess.status, 201, await approvalSuccess.clone().text());
    const approvalBody = await approvalSuccess.json();
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND payload->>'approvalId'=$1 AND event_type='approval.required'", [approvalBody.id])).rows[0].n, 1, 'successful manual approval creation has matching durable audit evidence');
    const approvalNotification = await storage.postgresQuery(`SELECT
      (SELECT count(*)::int FROM ag_alerts WHERE workspace_id='test' AND payload->>'approvalId'=$1 AND payload->>'notificationType'='approval.required') AS alerts,
      (SELECT count(*)::int FROM ag_alert_outbox o JOIN ag_alerts a ON a.workspace_id=o.workspace_id AND a.id=o.alert_id WHERE o.workspace_id='test' AND a.payload->>'approvalId'=$1 AND o.channel='webhook' AND o.status='queued') AS outbox`, [approvalBody.id]);
    assert.deepEqual(approvalNotification.rows[0], { alerts: 1, outbox: 1 }, 'approval notification and durable webhook delivery are created with the approval');
    const workerExpiryResponse = await post('/api/approvals', { agentId: registeredBody.id, action: `Worker expiry ${randomUUID()}`, risk: 'medium' }, { cookie: ownerCookie });
    assert.equal(workerExpiryResponse.status, 201, await workerExpiryResponse.clone().text());
    const workerExpiry = await workerExpiryResponse.json();
    await storage.postgresQuery("UPDATE ag_approvals SET payload=jsonb_set(payload,'{expiresAt}',to_jsonb($2::text)) WHERE workspace_id='test' AND id=$1", [workerExpiry.id, new Date(Date.now() - 1000).toISOString()]);
    const workerExpired = await repository.expireDueApprovals();
    assert.ok(workerExpired.some(item => item.id === workerExpiry.id), 'background expiry worker transitions the due approval');
    const workerExpiryNotice = await storage.postgresQuery(`SELECT
      (SELECT count(*)::int FROM ag_alerts WHERE workspace_id='test' AND payload->>'approvalId'=$1 AND payload->>'notificationType'='approval.expired') AS alerts,
      (SELECT count(*)::int FROM ag_alert_outbox o JOIN ag_alerts a ON a.workspace_id=o.workspace_id AND a.id=o.alert_id WHERE o.workspace_id='test' AND a.payload->>'approvalId'=$1 AND a.payload->>'notificationType'='approval.expired' AND o.channel='webhook') AS outbox`, [workerExpiry.id]);
    assert.deepEqual(workerExpiryNotice.rows[0], { alerts: 1, outbox: 1 }, 'background expiry commits one reviewer alert and one durable webhook notification');
    const incidentSuccess = await fetch(`${base}/api/incidents/${governanceIncidentId}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ status: 'investigating', note: 'Reviewed in test' }) });
    assert.equal(incidentSuccess.status, 200, await incidentSuccess.clone().text());
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND payload->>'incidentId'=$1 AND event_type='incident.updated'", [governanceIncidentId])).rows[0].n, 1, 'successful incident update has matching audit evidence');
    const alertSuccess = await post(`/api/alerts/${governanceAlertId}/acknowledge`, {}, { cookie: ownerCookie });
    assert.equal(alertSuccess.status, 200, await alertSuccess.clone().text());
    assert.equal((await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND payload->>'alertId'=$1 AND event_type='alert.acknowledged'", [governanceAlertId])).rows[0].n, 1, 'successful alert acknowledgement has matching audit evidence');
    const memberRoleSuccess = await fetch(`${base}/api/workspace/members/${memberBody.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: ownerCookie }, body: JSON.stringify({ role: 'operator' }) });
    assert.equal(memberRoleSuccess.status, 200, await memberRoleSuccess.clone().text());
    assert.equal((await storage.postgresQuery('SELECT role FROM ag_memberships WHERE workspace_id=$1 AND id=$2', ['test', memberBody.id])).rows[0].role, 'operator');
    const memberDeleteSuccess = await fetch(`${base}/api/workspace/members/${memberBody.id}`, { method: 'DELETE', headers: { cookie: ownerCookie } });
    assert.equal(memberDeleteSuccess.status, 204);
    const memberEvidence = await storage.postgresQuery("SELECT event_type,count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND message LIKE $1 GROUP BY event_type", [`%${memberEmail}%`]);
    assert.deepEqual(Object.fromEntries(memberEvidence.rows.map(row => [row.event_type, row.n])), { 'workspace.member.added': 1, 'workspace.member.removed': 1, 'workspace.member.role_updated': 1 }, 'membership create, role change, and removal each have durable audit evidence');
    const companyRotateSuccess = await post(`/api/companies/${companyBody.id}/gateway-credentials`, {}, { cookie: ownerCookie });
    assert.equal(companyRotateSuccess.status, 201, await companyRotateSuccess.clone().text());
    const companyRotateBody = await companyRotateSuccess.json();
    assert.ok(companyRotateBody.gatewayCredential);
    const companyCredentialAfter = await storage.postgresQuery('SELECT gateway_credential_hash FROM ag_companies WHERE workspace_id=$1 AND id=$2', ['test', companyBody.id]);
    assert.notEqual(companyCredentialAfter.rows[0].gateway_credential_hash, companyCredentialBefore.rows[0].gateway_credential_hash, 'successful company credential rotation is persisted');
    const provisionRotateSuccess = await post('/api/gateway/companies/register', { workspaceId: 'test', companyId: gatewayCompanyOkId, companyName: 'Gateway provision updated' }, integrationHeaders);
    assert.equal(provisionRotateSuccess.status, 201, await provisionRotateSuccess.clone().text());
    const provisionRotateBody = await provisionRotateSuccess.json();
    assert.ok(provisionRotateBody.gatewayCredential);
    const provisionAudit = await storage.postgresQuery("SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id=$1 AND payload->>'companyId'=$2 AND event_type IN ('company.gateway_provisioned','company.gateway_credential_rotated')", ['test', gatewayCompanyOkId]);
    assert.equal(provisionAudit.rows[0].n, 2, 'gateway company creation and credential rotation each append durable audit evidence');
    const rotatedResponse = await post(`/api/agents/${registeredBody.id}/credentials`, {}, { cookie: ownerCookie });
    assert.equal(rotatedResponse.status, 201, await rotatedResponse.clone().text());
    const rotated = await rotatedResponse.json();
    assert.ok(rotated.gatewayCredential);
    const rotatedState = await storage.postgresQuery('SELECT credential_hash FROM ag_agents WHERE workspace_id=$1 AND id=$2', ['test', registeredBody.id]);
    assert.notEqual(rotatedState.rows[0].credential_hash, credentialBefore.rows[0].credential_hash, 'successful rotation persists the new credential hash');
    assert.equal((await post(`/api/agents/${registeredBody.id}/connection/stop`, {}, { cookie: ownerCookie })).status, 200, 'connection stop commits with audit evidence');
    const stoppedState = await storage.postgresQuery("SELECT payload->'connection'->>'state' AS state FROM ag_agents WHERE workspace_id=$1 AND id=$2", ['test', registeredBody.id]);
    assert.equal(stoppedState.rows[0].state, 'stopped');
    runtimeServer = require('node:http').createServer((_req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ ok: true, status: 'running', currentTask: 'PostgreSQL connector integration test' })); });
    await new Promise(resolve => runtimeServer.listen(0, '127.0.0.1', resolve));
    const startResponse = await post(`/api/agents/${registeredBody.id}/connection/start`, { runtimeUrl: `http://127.0.0.1:${runtimeServer.address().port}/health` }, { cookie: ownerCookie });
    assert.equal(startResponse.status, 200, await startResponse.clone().text());
    assert.equal((await startResponse.json()).connection.state, 'connected');
    const connectorEvidence = await storage.postgresQuery("SELECT event_type,count(*)::int AS n FROM ag_audit_events WHERE workspace_id=$1 AND agent_id=$2 AND event_type IN ('agent.credential_rotated','connector.stopped','connector.start_requested','connector.connected') GROUP BY event_type", ['test', registeredBody.id]);
    assert.deepEqual(Object.fromEntries(connectorEvidence.rows.map(row => [row.event_type, row.n])), { 'agent.credential_rotated': 1, 'connector.connected': 1, 'connector.start_requested': 1, 'connector.stopped': 1 }, 'credential and connection transitions retain durable audit evidence');
    await new Promise(resolve => runtimeServer.close(resolve)); runtimeServer = null;
    const bulkNames = [`Bulk agent one ${randomUUID()}`, `Bulk agent two ${randomUUID()}`];
    const bulkResponse = await post('/api/agents/bulk', { companyId: 'company-1', team: 'integration-test', agents: [...bulkNames.map(name => ({ name })), { name: '  ' }] }, { cookie: ownerCookie });
    assert.equal(bulkResponse.status, 201, await bulkResponse.clone().text());
    const bulkBody = await bulkResponse.json();
    assert.equal(bulkBody.count, 2);
    assert.equal(bulkBody.rejected.length, 1);
    const bulkEvidence = await storage.postgresQuery('SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id=$1 AND agent_id=ANY($2::text[])', ['test', bulkBody.created.map(item => item.id)]);
    assert.equal(bulkEvidence.rows[0].n, 2, 'each committed bulk registration has its own audit event');

    // Gateway onboarding can create a new company and agent, but neither may
    // survive if either audit append fails.
    await storage.postgresQuery('CREATE TRIGGER test_reject_agentguard_audit BEFORE INSERT ON ag_audit_events FOR EACH ROW EXECUTE FUNCTION test_reject_agentguard_audit()');
    const gatewayRollbackCompany = `gateway-rollback-${randomUUID()}`;
    const gatewayRollback = await post('/api/gateway/agents/register', { workspaceId: 'test', companyId: gatewayRollbackCompany, companyName: 'Gateway rollback test', agentName: 'Gateway rollback sentinel' }, integrationHeaders);
    assert.equal(gatewayRollback.status, 503, await gatewayRollback.clone().text());
    const gatewayRollbackRows = await storage.postgresQuery('SELECT (SELECT count(*)::int FROM ag_companies WHERE workspace_id=$1 AND id=$2) AS companies,(SELECT count(*)::int FROM ag_agents WHERE workspace_id=$1 AND company_id=$2) AS agents', ['test', gatewayRollbackCompany]);
    assert.deepEqual(gatewayRollbackRows.rows[0], { companies: 0, agents: 0 }, 'failed gateway audit append rolls back newly provisioned company and agent');
    await storage.postgresQuery('DROP TRIGGER test_reject_agentguard_audit ON ag_audit_events');
    const gatewayCompanyId = `gateway-${randomUUID()}`;
    const gatewayResponse = await post('/api/gateway/agents/register', { workspaceId: 'test', companyId: gatewayCompanyId, companyName: 'Gateway integration test', agentName: 'Gateway registered agent' }, integrationHeaders);
    assert.equal(gatewayResponse.status, 201, await gatewayResponse.clone().text());
    const gatewayBody = await gatewayResponse.json();
    const gatewayState = await storage.postgresQuery("SELECT (SELECT count(*)::int FROM ag_companies WHERE workspace_id=$1 AND id=$2) AS companies,(SELECT count(*)::int FROM ag_agents WHERE workspace_id=$1 AND id=$3 AND company_id=$2) AS agents,(SELECT count(*)::int FROM ag_audit_events WHERE workspace_id=$1 AND (payload->>'companyId'=$2 OR agent_id=$3)) AS evidence", ['test', gatewayCompanyId, gatewayBody.agentId]);
    assert.deepEqual(gatewayState.rows[0], { companies: 1, agents: 1, evidence: 2 }, 'gateway company and agent registration each have durable audit evidence');
    const apiAction = { agentId: agent.id, ...workflowInput };
    const requestedResponse = await post('/api/guard/check', apiAction, integrationHeaders);
    assert.equal(requestedResponse.status, 202, `live policy-check API must hold the action for review: ${await requestedResponse.clone().text()}`);
    const requested = await requestedResponse.json();
    const pendingClaim = await post('/api/guard/executions/claim', apiAction, integrationHeaders);
    assert.equal(pendingClaim.status, 409, 'execution API must refuse an unapproved action');
    assert.equal((await pendingClaim.json()).decision, 'awaiting_approval');
    const approvedResponse = await post(`/api/approvals/${requested.approvalId}/approve`, { rationale: 'Reviewed test transaction' }, { cookie: reviewerCookie });
    assert.equal(approvedResponse.status, 200, 'reviewer session with reviewer membership can approve');
    const approvedAgain = await post(`/api/approvals/${requested.approvalId}/approve`, { rationale: 'duplicate decision' }, { cookie: reviewerCookie });
    assert.equal(approvedAgain.status, 409, 'approval decisions are single-use');
    const grantResponse = await post('/api/guard/executions/claim', apiAction, integrationHeaders);
    assert.equal(grantResponse.status, 200);
    const grant = await grantResponse.json();
    assert.equal(grant.decision, 'execute');
    const fakeReceipt = 'workflow-receipt';
    const effects = new Map();
    if (!effects.has(workflowInput.actionRef)) effects.set(workflowInput.actionRef, fakeReceipt);
    const completeResponse = await post('/api/guard/executions/complete', { agentId: agent.id, executionId: grant.executionId, success: true, result: { receipt: effects.get(workflowInput.actionRef) } }, integrationHeaders);
    assert.equal(completeResponse.status, 200);
    const duplicateClaim = await post('/api/guard/executions/claim', apiAction, integrationHeaders);
    assert.equal(duplicateClaim.status, 409);
    assert.equal((await duplicateClaim.json()).decision, 'duplicate_suppressed');
    assert.equal(effects.size, 1, 'the idempotent fake downstream applies one effect');

    const deniedInput = { ...apiAction, actionRef: 'denied-api-action', action: 'Issue refund' };
    const deniedRequest = await (await post('/api/guard/check', deniedInput, integrationHeaders)).json();
    const expiresDebug = await storage.postgresQuery(`SELECT payload->>'expiresAt' AS expiry FROM ag_approvals WHERE workspace_id='test' AND id=$1`, [deniedRequest.approvalId]);
    assert.ok(new Date(expiresDebug.rows[0].expiry).getTime() > Date.now(), `fresh API approval should not be expired: ${expiresDebug.rows[0].expiry}`);
    const deniedDecision = await post(`/api/approvals/${deniedRequest.approvalId}/deny`, { rationale: 'Test denial' }, { cookie: reviewerCookie });
    assert.equal(deniedDecision.status, 200, `${await deniedDecision.clone().text()} expiry=${expiresDebug.rows[0].expiry} now=${new Date().toISOString()}`);
    assert.equal((await post('/api/guard/executions/claim', deniedInput, integrationHeaders)).status, 403, 'denial must block execution at the API');

    // A daily action budget is reserved atomically before an approval-gated
    // action proceeds, blocks the next distinct action, and is released when
    // the reviewer denies the first request.
    const dailyPolicy = { id: 'daily-action-budget', workspaceId: 'test', name: 'One daily research action', effect: 'require_approval', enabled: true, version: 1, priority: 200, agentId: agent.id, actionType: 'research', resourcePattern: 'daily:report', dailyMaxActions: 1 };
    await storage.postgresQuery(`INSERT INTO ag_policies(workspace_id,id,agent_id,name,effect,enabled,version,priority,payload) VALUES ('test',$1,$2,$3,$4,true,1,200,$5::jsonb)`, [dailyPolicy.id, agent.id, dailyPolicy.name, dailyPolicy.effect, JSON.stringify(dailyPolicy)]);
    const dailyOne = { agentId: agent.id, actionRef: 'daily-budget-one', actionType: 'research', action: 'Generate daily report', resource: 'daily:report' };
    const dailyFirst = await post('/api/guard/check', dailyOne, integrationHeaders);
    assert.equal(dailyFirst.status, 202, await dailyFirst.clone().text());
    const dailyFirstBody = await dailyFirst.json();
    const dailyBlocked = await post('/api/guard/check', { ...dailyOne, actionRef: 'daily-budget-two', action: 'Generate second daily report' }, integrationHeaders);
    // Policy evaluation returns a decision document with HTTP 200. The
    // execution-claim endpoint is the enforcement boundary and returns 403
    // when a blocked action is actually attempted.
    assert.equal(dailyBlocked.status, 200, await dailyBlocked.clone().text());
    assert.match((await dailyBlocked.json()).reason, /Daily action budget exceeded/);
    assert.equal((await post(`/api/approvals/${dailyFirstBody.approvalId}/deny`, { rationale: 'Release test budget' }, { cookie: reviewerCookie })).status, 200);
    const dailyReleased = await post('/api/guard/check', { ...dailyOne, actionRef: 'daily-budget-three', action: 'Generate replacement daily report' }, integrationHeaders);
    assert.equal(dailyReleased.status, 202, 'denial releases the daily reservation for a replacement action');
    const dailyReservations = await storage.postgresQuery(`SELECT count(*)::int AS active FROM ag_budget_reservations WHERE workspace_id='test' AND policy_id=$1 AND released_at IS NULL`, [dailyPolicy.id]);
    assert.equal(dailyReservations.rows[0].active, 1, 'only the still-pending replacement action reserves daily budget');

    const expiredInput = { ...apiAction, actionRef: 'expired-api-action', action: 'Issue payment' };
    const expiredRequest = await (await post('/api/guard/check', expiredInput, integrationHeaders)).json();
    await storage.postgresQuery(`UPDATE ag_approvals SET payload=jsonb_set(payload,'{expiresAt}',to_jsonb($3::text)) WHERE workspace_id='test' AND id=$1 AND agent_id=$2`, [expiredRequest.approvalId, agent.id, new Date(Date.now() - 1000).toISOString()]);
    const lateReview = await post(`/api/approvals/${expiredRequest.approvalId}/approve`, { rationale: 'Late reviewer decision' }, { cookie: reviewerCookie });
    assert.equal(lateReview.status, 409, 'approval expiry is rechecked while deciding');
    assert.equal((await lateReview.json()).decision, 'expired');
    assert.equal((await post('/api/guard/executions/claim', expiredInput, integrationHeaders)).status, 403, 'expired approval cannot grant execution');
    const expiryNotice = await storage.postgresQuery(`SELECT
      (SELECT count(*)::int FROM ag_alerts WHERE workspace_id='test' AND payload->>'approvalId'=$1 AND payload->>'notificationType'='approval.expired') AS alerts,
      (SELECT count(*)::int FROM ag_alert_outbox o JOIN ag_alerts a ON a.workspace_id=o.workspace_id AND a.id=o.alert_id WHERE o.workspace_id='test' AND a.payload->>'approvalId'=$1 AND a.payload->>'notificationType'='approval.expired' AND o.channel='webhook') AS outbox`, [expiredRequest.approvalId]);
    assert.deepEqual(expiryNotice.rows[0], { alerts: 1, outbox: 1 }, 'expiry transaction creates one reviewer alert and a durable webhook notification');

    await storage.postgresQuery(`CREATE TABLE test_downstream_effects(action_ref text PRIMARY KEY, receipt text NOT NULL)`);
    const crashInput = { ...apiAction, actionRef: 'crash-action', action: 'Submit irreversible payment' };
    const crashRequest = await (await post('/api/guard/check', crashInput, integrationHeaders)).json();
    assert.equal((await post(`/api/approvals/${crashRequest.approvalId}/approve`, { rationale: 'Approve crash-boundary test' }, { cookie: reviewerCookie })).status, 200);
    const crashGrantResponse = await post('/api/guard/executions/claim', crashInput, integrationHeaders);
    assert.equal(crashGrantResponse.status, 200);
    const crashGrant = await crashGrantResponse.json();
    assert.equal(crashGrant.decision, 'execute');
    // Model the downstream committing its idempotent effect immediately before
    // the AgentGuard process dies, so /complete is never received.
    await storage.postgresQuery(`INSERT INTO test_downstream_effects(action_ref,receipt) VALUES ('crash-action','crash-receipt') ON CONFLICT (action_ref) DO NOTHING`);
    await storage.postgresQuery(`UPDATE ag_governed_actions SET claimed_at=now()-interval '2 minutes' WHERE workspace_id='test' AND action_ref='crash-action'`);

    const notExecutedInput = { ...apiAction, actionRef: 'not-executed-action', action: 'Create payment instruction' };
    const notExecutedRequest = await (await post('/api/guard/check', notExecutedInput, integrationHeaders)).json();
    assert.equal((await post(`/api/approvals/${notExecutedRequest.approvalId}/approve`, { rationale: 'Approve no-effect test' }, { cookie: reviewerCookie })).status, 200);
    assert.equal((await post('/api/guard/executions/claim', notExecutedInput, integrationHeaders)).status, 200);
    await storage.postgresQuery(`UPDATE ag_governed_actions SET claimed_at=now()-interval '2 minutes' WHERE workspace_id='test' AND action_ref='not-executed-action'`);

    const raceInput = { ...apiAction, actionRef: 'approval-race', action: 'Submit payment' };
    const raceRequest = await (await post('/api/guard/check', raceInput, integrationHeaders)).json();
    const raceDecisions = await Promise.all([
      post(`/api/approvals/${raceRequest.approvalId}/approve`, { rationale: 'Concurrent approve' }, { cookie: reviewerCookie }),
      post(`/api/approvals/${raceRequest.approvalId}/deny`, { rationale: 'Concurrent deny' }, { cookie: reviewerCookie }),
    ]);
    assert.deepEqual(raceDecisions.map(response => response.status).sort(), [200, 409], 'concurrent approve/deny decisions must have one winner');
    const raceStatus = await storage.postgresQuery(`SELECT status FROM ag_approvals WHERE workspace_id='test' AND id=$1`, [raceRequest.approvalId]);
    assert.ok(['approved', 'denied'].includes(raceStatus.rows[0].status));

    await create('approved-action');
    const claims = await Promise.all(Array.from({ length: 8 }, () => repository.claimGovernedAction({ workspaceId: 'test', agentId: 'agent-1', actionRef: 'approved-action', actionType: 'tool.call', action: 'Transfer funds', resource: 'tool:payments', executionId: randomUUID(), auditId: randomUUID() })));
    assert.equal(claims.filter(item => item.outcome === 'claimed').length, 1, 'exactly one concurrent caller receives an execution grant');
    assert.equal(claims.filter(item => item.outcome === 'duplicate').length, 7, 'duplicate deliveries are suppressed');
    const granted = claims.find(item => item.outcome === 'claimed').action;
    const completed = await repository.completeGovernedAction({ workspaceId: 'test', agentId: 'agent-1', executionId: granted.executionId, success: true, result: { receipt: 'receipt-1' }, auditId: randomUUID() });
    assert.equal(completed.outcome, 'completed');
    const repeatedCompletion = await repository.completeGovernedAction({ workspaceId: 'test', agentId: 'agent-1', executionId: granted.executionId, success: true, result: { receipt: 'receipt-1' }, auditId: randomUUID() });
    assert.equal(repeatedCompletion.outcome, 'duplicate');

    await create('denied-action', 'denied');
    const denied = await repository.claimGovernedAction({ workspaceId: 'test', agentId: 'agent-1', actionRef: 'denied-action', actionType: 'tool.call', action: 'Transfer funds', resource: 'tool:payments', executionId: randomUUID(), auditId: randomUUID() });
    assert.equal(denied.outcome, 'denied');

    await create('expired-action', 'denied', 'expired');
    const expired = await repository.claimGovernedAction({ workspaceId: 'test', agentId: 'agent-1', actionRef: 'expired-action', actionType: 'tool.call', action: 'Transfer funds', resource: 'tool:payments', executionId: randomUUID(), auditId: randomUUID() });
    assert.equal(expired.outcome, 'denied');

    const audit = await storage.postgresQuery(`SELECT event_type,count(*)::int AS count FROM ag_audit_events WHERE workspace_id='test' GROUP BY event_type`);
    assert.equal(audit.rows.find(row => row.event_type === 'execution.claimed')?.count, 4);
    assert.equal(audit.rows.find(row => row.event_type === 'execution.completed')?.count, 2);
    await repository.flushAudit();
    assert.ok((await storage.postgresQuery(`SELECT count(*)::int AS n FROM ag_audit_events WHERE workspace_id='test' AND event_type IN ('approval.required','approval.approved','approval.denied','approval.expired','execution.claimed','execution.completed')`)).rows[0].n >= 10, 'workflow, reviewer, and execution transitions have durable audit evidence');
    await repository.flushAudit();
    await new Promise(resolve => appServer.close(resolve));
    appServer = null;
    await storage.closePostgres();

    const child = await execFileAsync(process.execPath, [__filename, '--restart-probe'], { env: { ...process.env, DATABASE_URL: testUrl.toString() }, windowsHide: true, timeout: 60000 });
    console.log(child.stdout.trim());
    console.log('Governed PostgreSQL workflow passed: approvals, incident/alert/assessment writes, durable webhook outbox HTTP delivery/retry, governed execution, duplicate suppression, restart recovery, and evidence-backed reconciliation.');
  } finally {
    try { if (runtimeServer?.listening) await new Promise(resolve => { runtimeServer.close(resolve); runtimeServer.closeAllConnections?.(); }); } catch {}
    try { if (appServer?.listening) await new Promise(resolve => { appServer.close(resolve); appServer.closeAllConnections?.(); }); } catch {}
    try { await storage.closePostgres(); } catch {}
    await admin.query(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, [databaseName]);
    await admin.query(`DROP DATABASE IF EXISTS "${databaseName}"`);
    await admin.end();
  }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
