const { createHmac, timingSafeEqual } = require('node:crypto');
const { stableStringify } = require('./audit-integrity');

function secret() {
  return process.env.AGENTGUARD_AUDIT_CURSOR_SECRET || process.env.JWT_SECRET || 'local-development-session-secret-change-me';
}

function encodeCursor(payload) {
  const encoded = Buffer.from(stableStringify(payload)).toString('base64url');
  const signature = createHmac('sha256', secret()).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function decodeCursor(value, workspaceId, operation) {
  if (typeof value !== 'string' || value.length > 4096) throw new Error('Invalid audit cursor');
  const [encoded, supplied, ...extra] = value.split('.');
  if (!encoded || !supplied || extra.length) throw new Error('Invalid audit cursor');
  const expected = createHmac('sha256', secret()).update(encoded).digest();
  let actual;
  try { actual = Buffer.from(supplied, 'base64url'); } catch { throw new Error('Invalid audit cursor'); }
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new Error('Invalid audit cursor signature');
  let payload;
  try { payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); } catch { throw new Error('Invalid audit cursor'); }
  const position = payload.afterSequence ?? payload.beforeSequence;
  if (payload.workspaceId !== workspaceId || payload.operation !== operation || !Number.isSafeInteger(payload.upperSequence) || !Number.isSafeInteger(position) || position < 0 || position > payload.upperSequence + 1) throw new Error('Audit cursor does not match this workspace or request');
  return payload;
}

module.exports = { encodeCursor, decodeCursor };
