const { initializeStore, postgresQuery, usePostgres, closePostgres } = require('../storage');
const auditRepository = require('../repositories/audit');
const { verifyAuditPage } = require('../audit-integrity');

async function verifyAuditChain(workspaceId, pageSize = 1000) {
  const bounds = await auditRepository.bounds(workspaceId);
  let state = { workspaceId, previousHash: null, headHash: null, checked: 0, startSequence: null, endSequence: null };
  while (state.endSequence === null || state.endSequence < bounds.upperSequence) {
    const rows = await auditRepository.page(workspaceId, state.endSequence || 0, bounds.upperSequence, pageSize);
    if (!rows.length) break;
    const checked = verifyAuditPage(state, rows);
    state = checked.state;
    if (checked.failure) return { ok: false, ...state, failure: checked.failure, expectedCount: bounds.eventCount, expectedHeadHash: bounds.headHash };
  }
  if (state.checked !== bounds.eventCount) return { ok: false, ...state, failure: { sequence: state.endSequence, eventId: null, reason: `event count mismatch: checked ${state.checked}, expected ${bounds.eventCount}` }, expectedCount: bounds.eventCount, expectedHeadHash: bounds.headHash };
  if (state.headHash !== bounds.headHash) return { ok: false, ...state, failure: { sequence: state.endSequence, eventId: null, reason: 'head hash mismatch' }, expectedCount: bounds.eventCount, expectedHeadHash: bounds.headHash };
  return { ok: true, ...state, expectedCount: bounds.eventCount, expectedHeadHash: bounds.headHash };
}

if (require.main === module) {
  (async () => {
    if (!usePostgres) throw new Error('PostgreSQL storage is not enabled');
    await initializeStore();
    const workspaces = await postgresQuery('SELECT id FROM ag_workspaces ORDER BY id');
    const results = [];
    for (const workspace of workspaces.rows) results.push({ workspaceId: workspace.id, ...(await verifyAuditChain(workspace.id)) });
    const failed = results.find(result => !result.ok);
    console.log(JSON.stringify({ ok: !failed, results }));
    process.exitCode = failed ? 1 : 0;
  })().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => closePostgres().catch(() => {}));
}

module.exports = { verifyAuditChain };
