const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Client, Pool } = require('pg');

const sourceUrl = new URL(process.env.DATABASE_URL || '');
if (!sourceUrl.hostname) throw new Error('DATABASE_URL is required');
const databaseName = `agentguard_governed_test_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
const adminUrl = new URL(sourceUrl); adminUrl.pathname = '/postgres';
const testUrl = new URL(sourceUrl); testUrl.pathname = `/${databaseName}`;
const admin = new Client({ connectionString: adminUrl.toString() });

async function run() {
  await admin.connect();
  await admin.query(`CREATE DATABASE "${databaseName}"`);
  process.env.DATABASE_URL = testUrl.toString();
  process.env.AGENTGUARD_STORAGE = 'postgres';
  const storage = require('../storage');
  const repository = require('../repositories/governance');
  try {
    await storage.initializeStore();
    await storage.postgresQuery(`INSERT INTO ag_workspaces(id,name) VALUES ('test','Governed execution test') ON CONFLICT DO NOTHING`);

    async function create(actionRef, status = 'approved', decision = status) {
      const approvalId = randomUUID();
      const now = new Date().toISOString();
      await repository.upsertApproval({ id: approvalId, workspaceId: 'test', agentId: 'agent-1', policyId: 'policy-1', status, action: 'Transfer funds', actionRef, actionType: 'tool.call', resource: 'tool:payments', policyVersion: 1, createdAt: now, decidedAt: status === 'pending' ? null : now, decision });
      await repository.upsertGovernedAction({ id: randomUUID(), workspaceId: 'test', agentId: 'agent-1', actionRef, actionType: 'tool.call', action: 'Transfer funds', resource: 'tool:payments', policyId: 'policy-1', policyVersion: 1, approvalId, state: status === 'approved' ? 'approved' : status === 'denied' ? 'denied' : 'awaiting_approval', createdAt: now });
      return approvalId;
    }

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
    assert.equal(audit.rows.find(row => row.event_type === 'execution.claimed')?.count, 1);
    assert.equal(audit.rows.find(row => row.event_type === 'execution.completed')?.count, 1);
    await repository.flushAudit();
    await storage.closePostgres();

    // A fresh pool simulates a process restart and verifies the durable state.
    const restarted = new Pool({ connectionString: testUrl.toString() });
    const persisted = await restarted.query(`SELECT state,execution_id,payload->'result'->>'receipt' AS receipt FROM ag_governed_actions WHERE workspace_id='test' AND action_ref='approved-action'`);
    assert.deepEqual(persisted.rows[0], { state: 'completed', execution_id: granted.executionId, receipt: 'receipt-1' });
    await restarted.end();
    console.log('Governed PostgreSQL execution proof passed: approval, atomic claim, duplicate suppression, completion, denial, expiry, and restart persistence.');
  } finally {
    try { await storage.closePostgres(); } catch {}
    await admin.query(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, [databaseName]);
    await admin.query(`DROP DATABASE IF EXISTS "${databaseName}"`);
    await admin.end();
  }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
