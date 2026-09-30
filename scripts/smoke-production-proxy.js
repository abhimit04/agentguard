const { productionOriginErrors } = require('../deployment-config');

async function main() {
  const origin = process.env.AGENTGUARD_PUBLIC_ORIGIN;
  const redirect = process.env.OIDC_REDIRECT_URI;
  const errors = productionOriginErrors(origin, redirect);
  if (errors.length) throw new Error(errors.join('; '));

  const health = await fetch(`${origin}/api/health`, { redirect: 'error', signal: AbortSignal.timeout(15_000) });
  if (!health.ok) throw new Error(`Public health check returned HTTP ${health.status}`);
  const body = await health.json();
  if (!body?.ok) throw new Error('Public health check did not return { ok: true }');
  const hsts = health.headers.get('strict-transport-security') || '';
  if (!/max-age=\d{6,}/i.test(hsts)) throw new Error('HTTPS response is missing a long-lived Strict-Transport-Security header');
  const contentTypeOptions = health.headers.get('x-content-type-options');
  if (contentTypeOptions?.toLowerCase() !== 'nosniff') throw new Error('HTTPS response is missing X-Content-Type-Options: nosniff');

  const httpUrl = new URL(origin); httpUrl.protocol = 'http:';
  const redirectResponse = await fetch(httpUrl, { redirect: 'manual', signal: AbortSignal.timeout(15_000) });
  const location = redirectResponse.headers.get('location') || '';
  if (![301, 302, 307, 308].includes(redirectResponse.status) || !location.startsWith(origin)) {
    throw new Error(`HTTP did not redirect to the canonical HTTPS origin (status ${redirectResponse.status})`);
  }
  console.log(JSON.stringify({ ok: true, origin, health: health.status, hsts, httpRedirect: redirectResponse.status }, null, 2));
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
