const { randomBytes } = require('node:crypto');
const { spawn } = require('node:child_process');
const sessions = new Map();
const states = new Map();
const config = () => ({ issuer: process.env.OIDC_ISSUER || 'https://accounts.google.com', clientId: process.env.OIDC_CLIENT_ID, clientSecret: process.env.OIDC_CLIENT_SECRET, redirectUri: process.env.OIDC_REDIRECT_URI || 'http://localhost:3100/auth/callback', domain: process.env.GOOGLE_WORKSPACE_DOMAIN, sessionSecret: process.env.JWT_SECRET || 'local-development-session-secret-change-me' });

function cookie(name, value, maxAge = 3600) { return `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`; }
function redirect(res, location, headers = {}) { res.writeHead(302, { Location: location, ...headers }); res.end(); }
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(part => part.trim().split('=').map(decodeURIComponent)).filter(pair => pair.length === 2)); }

async function login(res) {
  const { clientId, redirectUri, issuer } = config();
  if (!clientId) return redirect(res, '/?auth=not-configured');
  const state = randomBytes(24).toString('hex'); states.set(state, Date.now());
  const url = new URL(`${issuer}/o/oauth2/v2/auth`);
  url.search = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' });
  return redirect(res, url.toString(), { 'Set-Cookie': cookie('agentguard_oauth_state', state, 600) });
}

async function callback(req, res, code, state) {
  const current = states.get(state); states.delete(state);
  const cookies = parseCookies(req); const settings = config();
  if (!current || Date.now() - current > 600000 || !state || cookies.agentguard_oauth_state !== state) return redirect(res, '/?auth=invalid-state');
  if (!code || !settings.clientId || !settings.clientSecret) return redirect(res, '/?auth=not-configured');
  const tokenResponse = await exchangeGoogleCode(settings, code);
  if (!tokenResponse.ok) return redirect(res, '/?auth=token-failed');
  const tokens = await tokenResponse.json();
  const { jwtVerify, createRemoteJWKSet } = await import('jose');
  const keys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
  const verified = await jwtVerify(tokens.id_token, keys, { issuer: ['https://accounts.google.com', 'accounts.google.com'], audience: settings.clientId });
  const claims = verified.payload;
  if (!claims.email_verified || (settings.domain && String(claims.hd || '').toLowerCase() !== settings.domain.toLowerCase())) return redirect(res, '/?auth=domain-rejected');
  const sessionId = randomBytes(32).toString('hex'); sessions.set(sessionId, { sub: claims.sub, email: claims.email, name: claims.name || claims.email, picture: claims.picture || null, createdAt: Date.now() });
  return redirect(res, '/', { 'Set-Cookie': [cookie('agentguard_oauth_state', '', 0), cookie('agentguard_session', sessionId, 28800)] });
}

function session(req) { const id = parseCookies(req).agentguard_session; return id ? sessions.get(id) || null : null; }
function logout(req, res) { sessions.delete(parseCookies(req).agentguard_session); return redirect(res, '/', { 'Set-Cookie': cookie('agentguard_session', '', 0) }); }

async function exchangeGoogleCode(settings, code) {
  const body = new URLSearchParams({ code, client_id: settings.clientId, client_secret: settings.clientSecret, redirect_uri: settings.redirectUri, grant_type: 'authorization_code' });
  try {
    return await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  } catch (error) {
    if (process.platform !== 'win32') throw error;
    const result = await new Promise((resolve, reject) => {
      const child = spawn('curl.exe', ['-sS', '-X', 'POST', '-H', 'Content-Type: application/x-www-form-urlencoded', '--data-binary', '@-', 'https://oauth2.googleapis.com/token'], { windowsHide: true });
      let stdout = ''; let stderr = '';
      child.stdout.on('data', chunk => { stdout += chunk; });
      child.stderr.on('data', chunk => { stderr += chunk; });
      child.once('error', reject);
      child.once('close', code => code === 0 ? resolve(stdout) : reject(new Error(stderr || `curl exited with ${code}`)));
      child.stdin.end(body.toString());
    });
    return new Response(result, { status: 200, headers: { 'content-type': 'application/json' } });
  }
}

module.exports.exchangeGoogleCode = exchangeGoogleCode;
module.exports = { login, callback, session, logout };
