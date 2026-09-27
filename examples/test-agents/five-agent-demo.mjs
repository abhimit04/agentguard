import { AgentGuard } from '../../sdk/node/agentguard.mjs';

// This is the only shared integration logic. In production these five
// configurations would come from each deployment's environment variables.
const configurations = [
  { id: 'demo-cricket-agent', name: 'Demo Cricket Agent', team: 'Sports', tools: ['cricbuzz'] },
  { id: 'demo-market-agent', name: 'Demo Market Agent', team: 'Research', tools: ['market-data'] },
  { id: 'demo-invoice-agent', name: 'Demo Invoice Agent', team: 'Finance', tools: ['erp', 'email'] },
  { id: 'demo-support-agent', name: 'Demo Support Agent', team: 'Customer Success', tools: ['zendesk', 'crm'] },
  { id: 'demo-hr-agent', name: 'Demo HR Agent', team: 'People Operations', tools: ['workday'] },
];

const agents = await Promise.all(configurations.map(async configuration => {
  const guard = await new AgentGuard(configuration).start();
  guard.onError = error => console.warn(`[${configuration.id}] heartbeat unavailable: ${error.message}`);
  await guard.report('heartbeat', `${configuration.name} is online for the fleet demo`);
  console.log(`[${configuration.id}] connected`);
  return guard;
}));

console.log(`\n${agents.length} test agents are connected. Open AgentGuard to view them.`);
console.log('Press Ctrl+C to stop the demo.');
process.on('SIGINT', () => { agents.forEach(agent => agent.stop()); process.exit(0); });
