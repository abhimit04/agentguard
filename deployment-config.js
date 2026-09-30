function productionOriginErrors(publicOriginValue, redirectUriValue) {
  const errors = [];
  let publicOrigin, redirectUri;
  try { publicOrigin = new URL(publicOriginValue || ''); } catch { errors.push('AGENTGUARD_PUBLIC_ORIGIN must be an absolute HTTPS origin'); }
  try { redirectUri = new URL(redirectUriValue || ''); } catch { errors.push('OIDC_REDIRECT_URI must be an absolute HTTPS callback URL'); }
  if (!publicOrigin || !redirectUri) return errors;
  if (publicOrigin.protocol !== 'https:' || publicOrigin.username || publicOrigin.password || publicOrigin.pathname !== '/' || publicOrigin.search || publicOrigin.hash) errors.push('AGENTGUARD_PUBLIC_ORIGIN must be a bare HTTPS origin without credentials, path, query, or fragment');
  if (redirectUri.protocol !== 'https:' || redirectUri.username || redirectUri.password || redirectUri.origin !== publicOrigin.origin || redirectUri.pathname !== '/auth/callback' || redirectUri.search || redirectUri.hash) errors.push('OIDC_REDIRECT_URI must be https://<AGENTGUARD_PUBLIC_ORIGIN host>/auth/callback with no query or fragment');
  return errors;
}

module.exports = { productionOriginErrors };
