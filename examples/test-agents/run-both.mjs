import { spawn } from 'node:child_process';

const scripts = ['market-research-agent.mjs', 'invoice-ops-agent.mjs'];
const children = scripts.map(script => spawn(process.execPath, [`examples/test-agents/${script}`], { stdio: 'inherit' }));
let failures = 0;
for (const child of children) child.on('exit', code => { if (code) failures += 1; if (children.every(item => item.exitCode !== null)) process.exitCode = failures ? 1 : 0; });
