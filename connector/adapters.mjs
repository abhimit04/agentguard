const attributeValue = value => value?.stringValue ?? value?.intValue ?? value?.doubleValue ?? value?.boolValue ?? value?.bytesValue ?? null;

export function readAttributes(attributes = []) {
  return Object.fromEntries(attributes.map(item => [item.key, attributeValue(item.value)]));
}

export const adapters = [
  { id: 'agentguard-events', label: 'AgentGuard Event API', path: '/events', description: 'Send normalized events from any runtime or integration.' },
  { id: 'opentelemetry-otlp', label: 'OpenTelemetry (OTLP/HTTP)', path: '/v1/traces', description: 'Ingest standard OTLP JSON traces from instrumented services and collectors.' },
];

export function resolveAgentId(resource, spans, knownAgents) {
  const attrs = readAttributes(resource?.attributes);
  const spanAttrs = spans.map(span => readAttributes(span.attributes));
  const explicitId = attrs['agentguard.agent.id'] ?? spanAttrs.find(item => item['agentguard.agent.id'])?.['agentguard.agent.id'];
  const serviceName = String(attrs['service.name'] || '').trim();
  if (!serviceName) throw new Error('OTLP resource is missing service.name');
  if (explicitId) {
    const existing = knownAgents.find(agent => agent.id === String(explicitId));
    return { id: String(explicitId), attrs, agent: existing || { name: serviceName, team: String(attrs['service.namespace'] || 'Discovered via OpenTelemetry'), tools: [], parentId: attrs['agentguard.parent.id'] ? String(attrs['agentguard.parent.id']) : null } };
  }
  const matching = knownAgents.filter(agent => agent.name?.toLowerCase() === serviceName.toLowerCase());
  if (matching.length > 1) throw new Error(`More than one registered agent is named ${serviceName}; add the resource attribute agentguard.agent.id to identify it.`);
  if (matching.length === 1) return { id: matching[0].id, attrs, agent: matching[0] };

  const slug = serviceName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'otel-agent';
  return {
    id: `otel-${slug}`,
    attrs,
    agent: {
      name: serviceName,
      team: String(attrs['service.namespace'] || attrs['deployment.environment.name'] || 'Discovered via OpenTelemetry'),
      tools: [],
      parentId: attrs['agentguard.parent.id'] ? String(attrs['agentguard.parent.id']) : null,
    },
  };
}

export function convertOtlpTraces(payload, knownAgents) {
  const events = [];
  for (const resourceGroup of payload.resourceSpans || []) {
    for (const scopeGroup of resourceGroup.scopeSpans || resourceGroup.instrumentationLibrarySpans || []) {
      const spans = scopeGroup.spans || [];
      if (!spans.length) continue;
      const resolved = resolveAgentId(resourceGroup.resource, spans, knownAgents);
      for (const span of spans) {
        const attrs = readAttributes(span.attributes);
        const start = BigInt(span.startTimeUnixNano || 0);
        const end = BigInt(span.endTimeUnixNano || span.startTimeUnixNano || 0);
        const statusCode = Number(span.status?.code || 0);
        const operation = String(attrs['gen_ai.operation.name'] || attrs['agent.operation'] || span.name || 'operation');
        const tool = attrs['gen_ai.tool.name'] || attrs['tool.name'] || attrs['agent.tool.name'] || null;
        const serviceName = String(resolved.agent?.name || resolved.attrs['service.name'] || resolved.id);
        const failed = statusCode === 2 || String(attrs['error'] || '').toLowerCase() === 'true';
        events.push({
          companyId: resolved.attrs['agentguard.company.id'] || resolved.agent?.companyId || 'default',
          agentId: resolved.id,
          eventType: failed ? 'agent.operation.failed' : tool ? 'tool.completed' : 'agent.operation.completed',
          message: `${serviceName}: ${operation}${tool ? ` via ${tool}` : ''}`,
          timestamp: start ? new Date(Number(start / 1_000_000n)).toISOString() : new Date().toISOString(),
          runId: span.traceId || null,
          taskId: span.spanId || null,
          actionRef: span.spanId || null,
          tool,
          resource: attrs['tool.resource'] || attrs['url.full'] || attrs['db.namespace'] || null,
          status: failed ? 'error' : 'success',
          durationMs: Number(end >= start ? end - start : 0n) / 1_000_000,
          metrics: {
            latencyMs: Number(end >= start ? end - start : 0n) / 1_000_000,
            inputTokens: Number(attrs['gen_ai.usage.input_tokens'] || attrs['llm.usage.prompt_tokens'] || 0),
            outputTokens: Number(attrs['gen_ai.usage.output_tokens'] || attrs['llm.usage.completion_tokens'] || 0),
            llmCalls: attrs['gen_ai.request.model'] || attrs['llm.request.model'] ? 1 : 0,
          },
          traceId: span.traceId || null,
          spanId: span.spanId || null,
          metadata: { ...resolved.attrs, ...attrs, ...(span.status?.message ? { statusMessage: span.status.message } : {}) },
          ...(resolved.agent ? { agent: resolved.agent } : {}),
        });
      }
    }
  }
  return events;
}
