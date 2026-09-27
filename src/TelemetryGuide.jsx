import React from 'react';

export default function TelemetryGuide() {
  const host = window.location.hostname;
  const collectorEndpoint = `http://${host}:4318`;
  const gatewayEndpoint = `http://${host}:3100/api/gateway/events`;
  const copy = value => navigator.clipboard?.writeText(value);

  return <section className="panel telemetry-guide">
    <div className="panel-header"><div><h2>Universal Agent Gateway</h2><p>One company-scoped contract for every framework, language, and agent runtime.</p></div><span className="agent-type-pill child">Contract v1.0</span></div>
    <div className="telemetry-options">
      <div><b>OpenTelemetry collector</b><p>For instrumented services in any supported language. Configure OTLP/HTTP traces to the collector.</p><code>{collectorEndpoint}</code><button className="text-button" onClick={() => copy(collectorEndpoint)}>Copy collector endpoint</button></div>
      <div><b>Agent Gateway</b><p>Send authenticated heartbeats, tasks, errors, latency, tokens, logs, and trace references.</p><code>{gatewayEndpoint}</code><button className="text-button" onClick={() => copy(gatewayEndpoint)}>Copy gateway endpoint</button></div>
    </div>
    <small className="telemetry-note">Every event carries <code>companyId</code> and <code>agentId</code> and is authenticated with that agent's credential. Heartbeats expire automatically; the dashboard requires no redesign when new companies or agents register.</small>
  </section>;
}
