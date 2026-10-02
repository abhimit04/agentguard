const test = require('node:test');
const assert = require('node:assert/strict');
const { auditHash, verifyAuditPage } = require('../audit-integrity');

function row(item, previousHash, sequence, workspaceId = 'workspace-a') {
  return {
    workspace_id: workspaceId,
    id: item.id,
    chain_sequence: sequence,
    previous_hash: previousHash,
    event_hash: auditHash(previousHash, item, workspaceId),
    payload: item
  };
}

test('audit verifier accepts a valid chain continued across bounded pages', () => {
  const first = { id: 'event-1', workspaceId: 'workspace-a', message: 'one' };
  const second = { id: 'event-2', workspaceId: 'workspace-a', message: 'two' };
  const third = { id: 'event-3', workspaceId: 'workspace-a', message: 'three' };
  const pageOne = verifyAuditPage(
    { workspaceId: 'workspace-a', previousHash: null, headHash: null, checked: 0, startSequence: null, endSequence: null },
    [row(first, null, 2), row(second, auditHash(null, first, 'workspace-a'), 5)]
  );
  assert.equal(pageOne.failure, null);
  assert.equal(pageOne.state.checked, 2);
  assert.equal(pageOne.state.startSequence, 2);
  assert.equal(pageOne.state.endSequence, 5);

  const pageTwo = verifyAuditPage(pageOne.state, [row(third, pageOne.state.headHash, 9)]);
  assert.equal(pageTwo.failure, null);
  assert.equal(pageTwo.state.checked, 3);
  assert.equal(pageTwo.state.endSequence, 9);
  assert.equal(pageTwo.state.headHash, auditHash(pageOne.state.headHash, third, 'workspace-a'));
});

test('audit verifier detects payload tampering even if the stored event hash is unchanged', () => {
  const original = { id: 'event-1', workspaceId: 'workspace-a', message: 'original' };
  const tampered = { ...original, message: 'modified' };
  const result = verifyAuditPage(
    { workspaceId: 'workspace-a', previousHash: null, headHash: null, checked: 0, startSequence: null, endSequence: null },
    [{ ...row(original, null, 1), payload: tampered }]
  );
  assert.equal(result.failure?.reason, 'event_hash mismatch');
  assert.equal(result.failure?.sequence, 1);
});

test('audit verifier detects a broken predecessor link', () => {
  const item = { id: 'event-2', workspaceId: 'workspace-a', message: 'second' };
  const result = verifyAuditPage(
    { workspaceId: 'workspace-a', previousHash: 'expected-predecessor', headHash: 'expected-predecessor', checked: 1, startSequence: 1, endSequence: 1 },
    [row(item, 'wrong-predecessor', 2)]
  );
  assert.equal(result.failure?.reason, 'previous_hash mismatch');
  assert.equal(result.failure?.sequence, 2);
});

test('audit event hashes are bound to their workspace', () => {
  const item = { id: 'event-1', workspaceId: 'workspace-a', message: 'one' };
  const wrongWorkspace = row(item, null, 1, 'workspace-b');
  const result = verifyAuditPage(
    { workspaceId: 'workspace-a', previousHash: null, headHash: null, checked: 0, startSequence: null, endSequence: null },
    [wrongWorkspace]
  );
  assert.equal(result.failure?.reason, 'workspace mismatch');
});
