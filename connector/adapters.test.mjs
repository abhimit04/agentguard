import test from 'node:test';
import assert from 'node:assert/strict';
import { convertOtlpTraces, resolveAgentId } from './adapters.mjs';

test('OTLP service name resolves to a unique registered agent', () => {
  const agents = [{ id: '5760', name: 'Market Research Agent' }];
  const resolved = resolveAgentId({ attributes: [{ key: 'service.name', value: { stringValue: 'Market Research Agent' } }] }, [], agents);
  assert.equal(resolved.id, '5760');
});

test('OTLP spans become generic AgentGuard events with trace and tool context', () => {
  const events = convertOtlpTraces({ resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'News Agent' } }] }, scopeSpans: [{ spans: [{ name: 'search', traceId: 'trace-1', spanId: 'span-1', startTimeUnixNano: '1000000', endTimeUnixNano: '9000000', attributes: [{ key: 'tool.name', value: { stringValue: 'news-search' } }], status: { code: 1 } }] }] }] }, [{ id: '9437', name: 'News Agent' }]);
  assert.equal(events.length, 1);
  assert.equal(events[0].agentId, '9437');
  assert.equal(events[0].eventType, 'tool.completed');
  assert.equal(events[0].runId, 'trace-1');
  assert.equal(events[0].durationMs, 8);
});

test('unknown services receive a stable discoverable AgentGuard identity', () => {
  const payload = { resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'Billing Worker' } }] }, scopeSpans: [{ spans: [{ name: 'invoice.run', startTimeUnixNano: '0', endTimeUnixNano: '0' }] }] }] };
  assert.equal(convertOtlpTraces(payload, [])[0].agentId, 'otel-billing-worker');
  assert.equal(convertOtlpTraces(payload, [])[0].agentId, convertOtlpTraces(payload, [])[0].agentId);
});
