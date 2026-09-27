import { AgentGuard } from '../../sdk/node/agentguard.mjs';

const guard = await AgentGuard.fromEnvironment().start();
guard.onError = error => console.error(`[${process.env.AGENTGUARD_AGENT_ID}] heartbeat error: ${error.message}`);
console.log(`[${process.env.AGENTGUARD_AGENT_ID}] process started and connected`);

const shutdown = () => { guard.stop(); process.exit(0); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
