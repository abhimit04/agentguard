const roles = ['owner', 'admin', 'reviewer', 'operator', 'viewer'];
const permissions = { read: roles, operate: ['owner', 'admin', 'operator'], review: ['owner', 'admin', 'reviewer'], configure: ['owner', 'admin'] };
function roleFor(user) {
  if (!user) return null;
  if (process.env.AGENTGUARD_OWNER_EMAIL && user.email.toLowerCase() === process.env.AGENTGUARD_OWNER_EMAIL.toLowerCase()) return 'owner';
  const entry = (process.env.AGENTGUARD_ROLE_MAP || '').split(',').map(item => item.trim().split(':')).find(([email]) => email && email.toLowerCase() === user.email.toLowerCase());
  return roles.includes(entry?.[1]) ? entry[1] : 'viewer';
}
function can(user, permission) { return permissions[permission]?.includes(roleFor(user)) || false; }
module.exports = { roleFor, can };
