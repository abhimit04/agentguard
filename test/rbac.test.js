const test = require('node:test');
const assert = require('node:assert/strict');
const { can, ensureBootstrapMembership, roleFor } = require('../rbac');

test('database membership takes precedence over legacy environment bootstrap roles', () => {
  const store = { memberships: [{ id: 'member-1', workspaceId: 'default', email: 'operator@example.com', role: 'operator' }] };
  const user = { email: 'operator@example.com' };
  assert.equal(roleFor(user, store, 'default'), 'operator');
  assert.equal(can(user, 'operate', store, 'default'), true);
  assert.equal(can(user, 'configure', store, 'default'), false);
});

test('owner environment configuration is persisted once as a bootstrap membership', () => {
  const previous = process.env.AGENTGUARD_OWNER_EMAIL;
  process.env.AGENTGUARD_OWNER_EMAIL = 'owner@example.com';
  const store = { memberships: [] };
  try {
    const member = ensureBootstrapMembership({ sub: 'subject-1', email: 'owner@example.com', name: 'Owner' }, store);
    assert.equal(member.role, 'owner');
    assert.equal(store.memberships.length, 1);
    assert.equal(ensureBootstrapMembership({ email: 'owner@example.com' }, store).id, member.id);
  } finally {
    if (previous === undefined) delete process.env.AGENTGUARD_OWNER_EMAIL;
    else process.env.AGENTGUARD_OWNER_EMAIL = previous;
  }
});
