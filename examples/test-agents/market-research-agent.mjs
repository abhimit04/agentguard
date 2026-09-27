import { checkAction, registerAndReport, report, waitForApproval } from './agent-client.mjs';

const agent = { id: 'market-research-agent', name: 'Market Research Agent', team: 'Growth intelligence', tools: ['Market data', 'Web search'] };
const ticker = process.env.TICKER || 'NVDA';
const actionRef = `market-research-${Date.now()}`;

try {
  await registerAndReport(agent);
  const decision = await checkAction(agent, 'research', `Research ${ticker} market outlook`, actionRef, `ticker:${ticker}`);
  console.log(`[${agent.id}] AgentGuard decision: ${decision.decision}`);
  if (decision.decision === 'awaiting_approval') {
    console.log(`[${agent.id}] Waiting for approval ${decision.approvalId} …`);
    const status = await waitForApproval(decision.approvalId);
    if (status !== 'approved') throw new Error(`Action ${status} by AgentGuard`);
  }
  if (decision.decision === 'block') throw new Error('Action blocked by AgentGuard policy');
  await report(agent, 'completed', `${agent.name} completed ${ticker} market research`, actionRef);
  console.log(`[${agent.id}] Completed safely.`);
} catch (error) {
  await report(agent, 'failed', `${agent.name} stopped: ${error.message}`, actionRef).catch(() => {});
  console.error(`[${agent.id}] ${error.message}`);
  process.exitCode = 1;
}
