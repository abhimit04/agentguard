const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('Caddy proxy keeps HTTPS security headers and private app upstream', () => {
  const caddyfile = fs.readFileSync(path.resolve(__dirname, '..', 'infra', 'caddy', 'Caddyfile'), 'utf8');
  assert.match(caddyfile, /Strict-Transport-Security/);
  assert.match(caddyfile, /X-Content-Type-Options/);
  assert.match(caddyfile, /reverse_proxy\s+app:3100/);
  assert.match(caddyfile, /header_up X-Forwarded-Proto \{scheme\}/);
  assert.match(caddyfile, /header_up X-Forwarded-Host \{host\}/);
});

test('production app is exposed only through the proxy network', () => {
  const compose = fs.readFileSync(path.resolve(__dirname, '..', 'docker-compose.yml'), 'utf8');
  const app = compose.slice(compose.indexOf('\n  app:'));
  assert.match(app, /expose:\s*\n\s+- "3100"/);
  assert.doesNotMatch(app, /ports:\s*\n\s+- .*3100/);
});
