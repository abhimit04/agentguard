# AgentGuard universal connector

The connector accepts a language-neutral AgentGuard event envelope at `POST /events` and OpenTelemetry OTLP/HTTP JSON traces at `POST /v1/traces`. An OpenTelemetry Collector can receive traces from multiple services and forward them through this connector.

## Start the connector and collector

Set `CONNECTOR_KEY` and `AGENTGUARD_API_KEY` in `connector/.env`, then run `docker compose up --build` from this directory. The connector listens on port 3200; the collector receives OTLP/HTTP on port 4318.

## Map trace services to AgentGuard agents

The connector matches OTLP resource attribute `service.name` to a unique registered AgentGuard agent name. For a deterministic mapping, set resource attribute `agentguard.agent.id` to the AgentGuard ID. Child agents can set `agentguard.parent.id`. If no registered agent matches, the connector creates a registered inventory record using a stable `otel-<service-name>` ID. The first accepted span marks that record Connected.

Useful resource attributes include `service.name`, `service.namespace`, `deployment.environment.name`, and `agentguard.agent.id`. Tool spans can use `gen_ai.tool.name`, `tool.name`, or `agent.tool.name`; run and span identifiers become the event run and task references.

This path works with any language or platform that exports OTLP. The connector does not inspect arbitrary process memory or infer tool calls that the agent runtime does not emit as telemetry. In those cases, use the generic `/events` contract or add an OpenTelemetry instrumentation/collector integration for that runtime.

## Persistent multi-tenant company gateway

Deploy `company-gateway.mjs` once per company or network. It authenticates with a company gateway credential, polls `GET /api/gateway/config`, and dynamically starts or stops monitoring registered agent URLs. Adding another agent to that company does not restart the gateway.

Required environment:

```ini
AGENTGUARD_URL=http://agentguard:3100
AGENTGUARD_COMPANY_ID=company-a
AGENTGUARD_GATEWAY_CREDENTIAL=ag_live_...
```

Docker Compose deployments can start the optional profile with `docker compose --profile company-gateway up -d --build`. The service uses `restart: unless-stopped` and refreshes its registry configuration every ten seconds.
