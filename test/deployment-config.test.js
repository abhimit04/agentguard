const test = require('node:test');
const assert = require('node:assert/strict');
const { productionOriginErrors } = require('../deployment-config');

test('production accepts a public HTTPS origin with its exact Google callback', () => {
  assert.deepEqual(productionOriginErrors('https://guard.example.com', 'https://guard.example.com/auth/callback'), []);
});

test('production rejects non-TLS origins, origin mismatch, and non-callback paths', () => {
  assert.ok(productionOriginErrors('http://guard.example.com', 'http://guard.example.com/auth/callback').length > 0);
  assert.ok(productionOriginErrors('https://guard.example.com', 'https://other.example.com/auth/callback').length > 0);
  assert.ok(productionOriginErrors('https://guard.example.com', 'https://guard.example.com/callback').length > 0);
  assert.ok(productionOriginErrors('https://guard.example.com/path', 'https://guard.example.com/path/auth/callback').length > 0);
});
