# Production foundation

The Compose stack provides PostgreSQL and scheduled local backups:

```powershell
Copy-Item .env.example .env
# Set POSTGRES_PASSWORD and the identity/deployment secrets in .env
docker compose up -d postgres backup
```

The PostgreSQL schema is workspace-scoped by design. The application migration from the current SQLite store should create one initial workspace, import agents/policies/approvals/events into it, and then require a workspace context on every query.

The next application layer adds Google Workspace OIDC login, signed JWT sessions, and membership checks for `owner`, `admin`, `reviewer`, `operator`, and `viewer` roles. Restrict the verified email domain with `GOOGLE_WORKSPACE_DOMAIN`. TLS should terminate at the deployment reverse proxy; never expose PostgreSQL directly to the public network.

Set `AGENTGUARD_REQUIRE_AUTH=true` only after Google OAuth credentials and the callback URL have been verified. This redirects unauthenticated dashboard visitors to `/auth/login` and protects `/api/dashboard` with a 401 response.
