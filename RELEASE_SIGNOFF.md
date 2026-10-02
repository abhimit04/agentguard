# AgentGuard release sign-off

Updated: 2026-10-02

## Verified

- [x] Full local test suite passes (56 tests).
- [x] Signed backup manifests are enforced in CI.
- [x] Weekly PostgreSQL restore drill is configured.
- [x] Protected staging SQL restore passed: 47 agents, 17 approvals, 11,413 audit events.
- [x] Audit chain verified after staging restore.
- [x] Governed approval → claim → completion smoke passed after restore.
- [x] Scratch restore database cleanup passed.
- [x] Backup freshness check and failure summary are configured.
- [x] Caddy HTTPS headers and private upstream routing are covered by tests.
- [x] Legacy compatibility writes are blocked and the mirror is quarantined.

## Required before production sign-off

- [ ] Client approves the compatibility-store reconciliation and retirement plan.
- [ ] Final legacy archive is stored outside the runtime host.
- [ ] Backup signing private key is held in independent secret storage.
- [ ] Backup failure/staleness notification destination is configured and tested.
- [ ] RPO/RTO targets are agreed and measured with a timed restore.
- [ ] Staging OAuth sign-in/sign-out, secure cookies, certificate renewal, and direct-upstream blocking are verified.
- [ ] Sustained multi-instance telemetry load test records latency, queue depth, rejection counts, and noisy-neighbor isolation.

Do not mark a gate complete because a route or UI panel exists; attach the command
output or hosted run evidence for each checked item.
