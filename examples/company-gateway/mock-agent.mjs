import http from 'node:http';

const port = Number(process.argv[2]);
const name = process.argv[3] || `Demo Agent ${port}`;
if (!port) throw new Error('Usage: node mock-agent.mjs <port> <name>');

http.createServer((req, res) => {
  if (req.url !== '/health') { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ ok: true, name, status: 'ready', version: '1.0.0' }));
}).listen(port, '127.0.0.1', () => console.log(`${name} listening on ${port}`));
