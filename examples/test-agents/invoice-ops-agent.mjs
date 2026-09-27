import { checkAction, registerAndReport, report, waitForApproval } from './agent-client.mjs';

const agent = { id: 'invoice-ops-agent', name: 'Invoice Operations Agent', team: 'Finance operations', tools: ['ERP', 'Email'] };
const actionRef = `invoice-ops-${Date.now()}`;

try {
  await registerAndReport(agent);
  const decision = await checkAction(agent, 'tool_call', 'Reconcile the latest supplier invoice batch', actionRef, 'tool:erp');
  console.log(`[${agent.id}] AgentGuard decision: ${decision.decision}`);
  if (decision.decision === 'awaiting_approval') {
    console.log(`[${agent.id}] Waiting for approval ${decision.approvalId} …`);
    const status = await waitForApproval(decision.approvalId);
    if (status !== 'approved') throw new Error(`Action ${status} by AgentGuard`);
  }
  if (decision.decision === 'block') throw new Error('Action blocked by AgentGuard policy');
  await report(agent, 'completed', `${agent.name} completed invoice reconciliation`, actionRef);
  console.log(`[${agent.id}] Completed safely.`);
} catch (error) {
  await report(agent, 'failed', `${agent.name} stopped: ${error.message}`, actionRef).catch(() => {});
  console.error(`[${agent.id}] ${error.message}`);
  process.exitCode = 1;
}
