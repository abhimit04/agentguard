const { initializeStore, readStore, postgresQuery, usePostgres } = require('../storage');

(async () => {
  if (!usePostgres) throw new Error('PostgreSQL storage is not enabled');
  await initializeStore();
  const required = ['ag_workspaces', 'ag_companies', 'ag_agents', 'ag_policies', 'ag_approvals', 'ag_governed_actions', 'ag_incidents', 'ag_alerts', 'ag_alert_deliveries', 'ag_audit_events'];
  const counts = {};
  for (const table of required) {
    const result = await postgresQuery(`SELECT count(*)::int AS count FROM ${table}`);
    counts[table] = result.rows[0].count;
  }
  const broken = await postgresQuery(`SELECT count(*)::int AS count FROM ag_audit_events WHERE event_hash IS NULL`);
  if (!counts.ag_workspaces) throw new Error('No PostgreSQL workspace found');
  if (!counts.ag_companies) throw new Error('No PostgreSQL company found');
  if (!counts.ag_agents) throw new Error('No PostgreSQL agents found');
  if (broken.rows[0].count) throw new Error(`${broken.rows[0].count} audit events are missing integrity hashes`);
  const hydrated = readStore();
  if (hydrated.agents.length !== counts.ag_agents) throw new Error(`Relational startup hydrated ${hydrated.agents.length} of ${counts.ag_agents} agents`);
  console.log(JSON.stringify({ ok: true, storage: 'postgres-relational', counts, hydratedAgents: hydrated.agents.length, unhashedAuditEvents: 0 }));
  process.exit(0);
})().catch(error => { console.error(error.message); process.exit(1); });
