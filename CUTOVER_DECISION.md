# Compatibility-store cutover decision

Date: 2026-10-02

## Decision

The relational PostgreSQL tables are the authoritative AgentGuard store. The legacy
`agentguard_records` mirror is quarantined and must not receive runtime writes.

## Rationale

The staging reconciliation found divergent counts and payloads between the two
stores. Automatically importing, merging, or deleting records could lose history
or rewrite the audit narrative. PostgreSQL already passed the protected restore
drill, audit-chain verification, and governed-write smoke test.

## Operational rules

- Do not delete `agentguard_records` yet.
- Do not import divergent rows automatically.
- Keep the read-only inspection and archive evidence available for review.
- Treat relational PostgreSQL as the source of truth for new reads and writes.
- Require client approval and a final backup/restore drill before dropping the
  compatibility table.

## Exit criteria for final removal

1. Client signs off on the reconciliation report and any records to retain.
2. A final archive of the legacy table and manifest is stored outside the runtime.
3. A fresh PostgreSQL backup and restore drill passes after the table is removed.
4. Runtime startup no longer checks or references the compatibility table.
