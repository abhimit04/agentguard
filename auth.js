const { createHmac, randomBytes, timingSafeEqual } = require('node:crypto');
const { spawn } = require('node:child_process');
const SESSION_MAX_AGE_MS = 8 * 60 * 60 * 1000;
const config = () => ({ issuer: process.env.OIDC_ISSUER || 'https://accounts.google.com', clientId: process.env.OIDC_CLIENT_ID, clientSecret: process.env.OIDC_CLIENT_SECRET, redirectUri: process.env.OIDC_REDIRECT_URI || 'http://localhost:3100/auth/callback', domain: process.env.GOOGLE_WORKSPACE_DOMAIN, sessionSecret: process.env.JWT_SECRET || 'local-development-session-secret-change-me' });

function cookie(name, value, maxAge = 3600) { return `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`; }
function redirect(res, location, headers = {}) { res.writeHead(302, { Location: location, ...headers }); res.end(); }
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(part => part.trim().split('=').map(decodeURIComponent)).filter(pair => pair.length === 2)); }
function signedToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', config().sessionSecret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [encoded, supplied] = token.split('.');
  const expected = createHmac('sha256', config().sessionSecret).update(encoded).digest('base64url');
  const actualBuffer = Buffer.from(supplied || ''); const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length || !timingSafeEqual(actualBuffer, expectedBuffer)) return null;
  try { return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); } catch { return null; }
}

async function login(res) {
  const { clientId, redirectUri, issuer } = config();
  if (!clientId) return redirect(res, '/?auth=not-configured');
  const state = signedToken({ nonce: randomBytes(24).toString('hex'), createdAt: Date.now(), purpose: 'oauth-state' });
  const url = new URL(`${issuer}/o/oauth2/v2/auth`);
  url.search = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' });
  return redirect(res, url.toString(), { 'Set-Cookie': cookie('agentguard_oauth_state', state, 600) });
}

async function callback(req, res, code, state) {
  const cookies = parseCookies(req); const settings = config();
  const current = verifyToken(state);
  if (!current || current.purpose !== 'oauth-state' || Date.now() - current.createdAt > 600000 || !state || cookies.agentguard_oauth_state !== state) return redirect(res, '/?auth=invalid-state');
  if (!code || !settings.clientId || !settings.clientSecret) return redirect(res, '/?auth=not-configured');
  const tokenResponse = await exchangeGoogleCode(settings, code);
  if (!tokenResponse.ok) return redirect(res, '/?auth=token-failed');
  const tokens = await tokenResponse.json();
  const { jwtVerify, createRemoteJWKSet } = await import('jose');
  const keys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
  const verified = await jwtVerify(tokens.id_token, keys, { issuer: ['https://accounts.google.com', 'accounts.google.com'], audience: settings.clientId });
  const claims = verified.payload;
  if (!claims.email_verified || (settings.domain && String(claims.hd || '').toLowerCase() !== settings.domain.toLowerCase())) return redirect(res, '/?auth=domain-rejected');
  const sessionToken = signedToken({ sub: claims.sub, email: claims.email, name: claims.name || claims.email, picture: claims.picture || null, createdAt: Date.now(), purpose: 'session' });
  return redirect(res, '/', { 'Set-Cookie': [cookie('agentguard_oauth_state', '', 0), cookie('agentguard_session', sessionToken, 28800)] });
}

function session(req) {
  const current = verifyToken(parseCookies(req).agentguard_session);
  if (!current || current.purpose !== 'session') return null;
  if (Date.now() - current.createdAt > SESSION_MAX_AGE_MS) return null;
  return current;
}
function logout(req, res) { return redirect(res, '/', { 'Set-Cookie': cookie('agentguard_session', '', 0) }); }

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
