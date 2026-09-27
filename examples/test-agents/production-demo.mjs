import { spawn } from 'node:child_process';

const agents = [
  ['prodtest-cricket-agent', 'Production Test Cricket Agent', 'Sports', 'cricbuzz'],
  ['prodtest-market-agent', 'Production Test Market Agent', 'Research', 'market-data'],
  ['prodtest-invoice-agent', 'Production Test Invoice Agent', 'Finance', 'erp,email'],
  ['prodtest-support-agent', 'Production Test Support Agent', 'Customer Success', 'zendesk,crm'],
  ['prodtest-hr-agent', 'Production Test HR Agent', 'People Operations', 'workday'],
];

const children = agents.map(([id, name, team, tools]) => spawn(process.execPath, ['examples/test-agents/fleet-worker.mjs'], {
  stdio: 'inherit',
  env: { ...process.env, AGENTGUARD_AGENT_ID: id, AGENTGUARD_AGENT_NAME: name, AGENTGUARD_AGENT_TEAM: team, AGENTGUARD_AGENT_TOOLS: tools },
}));

console.log(`Started ${children.length} separate AgentGuard worker processes.`);
console.log('This terminal represents a production-style fleet supervisor. Press Ctrl+C to stop all workers.');
const stopAll = () => { children.forEach(child => child.kill('SIGTERM')); process.exit(0); };
process.on('SIGINT', stopAll);
process.on('SIGTERM', stopAll);
