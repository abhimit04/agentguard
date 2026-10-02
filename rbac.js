const { randomUUID } = require('node:crypto');

const roles = ['owner', 'admin', 'reviewer', 'operator', 'viewer'];
const permissions = { read: roles, operate: ['owner', 'admin', 'operator'], review: ['owner', 'admin', 'reviewer'], exportEvidence: ['owner', 'admin', 'reviewer'], configure: ['owner', 'admin'], manageMembers: ['owner', 'admin'], createLegalHold: ['owner', 'admin'], releaseLegalHold: ['owner'] };

function bootstrapRoleFor(user) {
  if (!user) return null;
  const email = String(user.email || '').toLowerCase();
  if (process.env.AGENTGUARD_OWNER_EMAIL && email === process.env.AGENTGUARD_OWNER_EMAIL.toLowerCase()) return 'owner';
  const entry = (process.env.AGENTGUARD_ROLE_MAP || '').split(',').map(item => item.trim().split(':')).find(([mapped]) => mapped && mapped.toLowerCase() === email);
  return roles.includes(entry?.[1]) ? entry[1] : null;
}

function roleFor(user, store, workspaceId = 'default') {
  if (!user) return null;
  const email = String(user.email || '').toLowerCase();
  const membership = store?.memberships?.find(item => item.workspaceId === workspaceId && String(item.email || '').toLowerCase() === email);
  return roles.includes(membership?.role) ? membership.role : bootstrapRoleFor(user);
}

function can(user, permission, store, workspaceId) {
  return permissions[permission]?.includes(roleFor(user, store, workspaceId)) || false;
}

function ensureBootstrapMembership(user, store, workspaceId = 'default') {
  if (!user || !store) return null;
  const email = String(user.email || '').trim().toLowerCase();
  const existing = store.memberships.find(item => item.workspaceId === workspaceId && String(item.email || '').toLowerCase() === email);
  if (existing) return existing;
  const role = bootstrapRoleFor(user);
  if (!role) return null;
  const membership = { id: randomUUID(), workspaceId, email, name: user.name || email, subject: user.sub || null, role, createdAt: new Date().toISOString(), source: 'environment-bootstrap' };
  store.memberships.push(membership);
  return membership;
}

module.exports = { roles, permissions, bootstrapRoleFor, roleFor, can, ensureBootstrapMembership };
