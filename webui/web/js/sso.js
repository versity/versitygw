// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

/**
 * Single sign-on through an OpenID Connect provider.
 *
 * The browser is a public client: it runs the authorization code flow with
 * PKCE (S256) against the provider, then trades the ID token for temporary
 * credentials with AssumeRoleWithWebIdentity on the standalone IAM service.
 * From there the session works like a key-based one, except that it signs
 * with a session token and has to be renewed before it expires.
 *
 * The provider sends the user back to the login page itself; there is no
 * callback route. Only the login page carries window.__VGWCONFIG__, so
 * everything renewal and sign-out need later is copied into sessionStorage
 * at sign-in.
 *
 * Requires: api.js (the api instance, STS_API_VERSION, parseXmlErrorCode).
 */

// sessionStorage keys. api.logout() clears everything under vgw_sso_.
const SSO_SESSION_KEY = 'vgw_sso_session';
const SSO_PENDING_KEY = 'vgw_sso_pending';

// Renew this long before the credentials expire, and start warning a
// session that cannot renew itself.
const SSO_RENEW_LEAD_MS = 5 * 60 * 1000;
// Credentials this close to expiry are renewed before they sign anything.
const SSO_SIGN_LEAD_MS = 60 * 1000;

const SSO_ROLE_ARN_PATTERN = /^arn:aws:iam::\d{12}:role\/\S+$/;
const SSO_SESSION_NAME_FALLBACK = 'webui-sso';

/**
 * An error whose message is meant for the user as is.
 */
class SSOError extends Error {
  constructor(message, code = null) {
    super(message);
    this.code = code;
  }
}

class VersitySSO {
  constructor() {
    this._renewing = null;
    this._timer = null;
    this._bannerTimer = null;
    this._redirecting = false;
    this._watchingVisibility = false;
  }

  // ============================================
  // Configuration and state
  // ============================================

  /**
   * The SSO settings the server injected into the login page, or null when
   * SSO is not configured (or this is not the login page).
   */
  pageConfig() {
    const cfg = window.__VGWCONFIG__ || {};
    return cfg.oidc && cfg.oidc.issuer && cfg.oidc.clientId ? cfg.oidc : null;
  }

  /**
   * The signed-in SSO session's state, or null for a key-based session.
   */
  session() {
    return readSSOJSON(SSO_SESSION_KEY);
  }

  _saveSession(session) {
    sessionStorage.setItem(SSO_SESSION_KEY, JSON.stringify(session));
  }

  /**
   * Make temporary credentials this tab's credentials. Sign-in and renewal
   * both store them through api.setCredentials(), the same path as a
   * key-based sign-in with an IAM endpoint. There is no admin endpoint,
   * since standalone IAM manages this deployment.
   */
  _useCredentials(creds, { region, s3Endpoint, addressingStyle, iamEndpoint }) {
    api.setCredentials('', creds.accessKey, creds.secretKey, region);
    api.setSessionToken(creds.sessionToken, creds.expiration);
    api.setS3Endpoint(s3Endpoint);
    api.setAddressingStyle(addressingStyle);
    api.setIAMEndpoint(iamEndpoint);
  }

  /**
   * What the account menu shows for an SSO session, or null.
   */
  userInfo() {
    const session = this.session();
    if (!session || !api.credentials?.sessionToken) return null;
    const user = session.user || {};
    return {
      name: user.email || user.name || user.preferred_username || user.sub || 'SSO user',
      roleName: roleNameFromArn(session.roleArn),
      expiration: api.credentials.expiration,
    };
  }

  /**
   * The login page's own URL, which is the default redirect URI: origin plus
   * the base path the server rendered into <base href>, so it covers every
   * path prefix the WebUI can be mounted under.
   */
  loginPageURL() {
    const url = new URL('.', document.baseURI);
    url.search = '';
    url.hash = '';
    return url.toString();
  }

  // ============================================
  // Sign-in
  // ============================================

  /**
   * Start the authorization code flow and leave for the provider.
   * @param {Object} opts
   * @param {Object} opts.config - The SSO settings (pageConfig() or stored)
   * @param {string} opts.iamEndpoint - IAM service the token is exchanged at
   * @param {string} opts.s3Endpoint - Optional S3 endpoint for the session
   * @param {string} opts.region - Region for S3 signing
   * @param {string} opts.addressingStyle - 'path' or 'virtual-host'
   * @param {string} [opts.redirectUri] - Redirect URI of an earlier sign-in
   * @param {string} [opts.returnTo] - Page to go back to afterwards
   * @param {string} [opts.roleArn] - Role to keep, when still offered
   * @param {number} [opts.attempt] - Restarts made for an expired ID token
   */
  async begin(opts) {
    const { config, iamEndpoint } = opts;
    if (!iamEndpoint) {
      throw new SSOError('Single sign-on needs the IAM API endpoint. Set it under Advanced Options.');
    }

    const redirectUri = opts.redirectUri || config.redirectUri || this.loginPageURL();
    const redirectOrigin = new URL(redirectUri).origin;
    if (redirectOrigin !== window.location.origin) {
      throw new SSOError(`Single sign-on is set up for ${redirectOrigin}. Open the WebUI there to sign in.`);
    }

    const endpoints = await this._discover(config.issuer);
    const state = randomSSOToken(32);
    const nonce = randomSSOToken(32);
    const codeVerifier = randomSSOToken(48);
    const codeChallenge = base64ToBase64url(await api.sha256Base64(codeVerifier));

    sessionStorage.setItem(SSO_PENDING_KEY, JSON.stringify({
      state,
      nonce,
      codeVerifier,
      redirectUri,
      config,
      endpoints,
      iamEndpoint,
      s3Endpoint: opts.s3Endpoint || '',
      region: opts.region || 'us-east-1',
      addressingStyle: opts.addressingStyle || 'path',
      returnTo: opts.returnTo || null,
      roleArn: opts.roleArn || null,
      attempt: opts.attempt || 0,
    }));

    const url = new URL(endpoints.authorization);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', config.clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', config.scopes || 'openid profile email');
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    window.location.assign(url.toString());
  }

  /**
   * Whether this page load is the provider sending the user back.
   */
  isCallback() {
    const params = new URLSearchParams(window.location.search);
    return params.has('state') && (params.has('code') || params.has('error'));
  }

  /**
   * Process the provider's response on the login page: check it belongs to
   * the sign-in this browser started, exchange the code, and work out the
   * roles the user may pick from.
   * @returns {Object} The sign-in to pass to complete(), with roles[] holding
   *   the candidate role ARNs (one means no choice is needed)
   */
  async handleCallback() {
    const params = new URLSearchParams(window.location.search);
    // The code is single-use and the state is spent, but neither should stay
    // in the address bar, the history or a bookmark.
    window.history.replaceState(null, '', window.location.pathname + window.location.hash);

    const pending = readSSOJSON(SSO_PENDING_KEY);
    sessionStorage.removeItem(SSO_PENDING_KEY);

    const error = params.get('error');
    if (error) {
      if (error === 'access_denied') {
        throw new SSOError('Sign-in cancelled.', error);
      }
      throw new SSOError(params.get('error_description') || `The identity provider refused the sign-in (${error}).`, error);
    }
    if (!pending || params.get('state') !== pending.state) {
      throw new SSOError('Sign-in failed: the identity provider\'s response does not match a sign-in started in this browser tab. Please try again.');
    }

    const tokens = await this._tokenRequest(pending.endpoints.token, {
      grant_type: 'authorization_code',
      code: params.get('code'),
      redirect_uri: pending.redirectUri,
      client_id: pending.config.clientId,
      code_verifier: pending.codeVerifier,
    });
    if (!tokens.id_token) {
      throw new SSOError('The identity provider returned no ID token. Check that this client may use the openid scope.');
    }
    const claims = decodeSSOJWT(tokens.id_token);
    if (claims.nonce !== pending.nonce) {
      throw new SSOError('Sign-in failed: the ID token was not issued for this sign-in. Please try again.');
    }

    return { pending, tokens, claims, roles: this._candidateRoles(claims, pending.config, pending.roleArn) };
  }

  /**
   * Finish a sign-in from handleCallback() with the chosen role: get the
   * temporary credentials and store them as this tab's session.
   */
  async complete(signIn, roleArn) {
    const { pending, tokens, claims } = signIn;

    let creds;
    try {
      creds = await this._assumeRole(pending.iamEndpoint, roleArn, tokens.id_token, claims, pending.config);
    } catch (e) {
      // The provider issued the token moments ago, so an expired one is
      // clock skew or a slow sign-in; one fresh round usually fixes it.
      if (e.code === 'ExpiredTokenException' && !pending.attempt) {
        await this.begin({ ...pending, attempt: 1 });
        const restarted = new SSOError('Signing in again…');
        restarted.restarted = true;
        throw restarted;
      }
      throw e;
    }

    this._useCredentials(creds, pending);

    this._saveSession({
      config: pending.config,
      endpoints: pending.endpoints,
      redirectUri: pending.redirectUri,
      roleArn,
      refreshToken: tokens.refresh_token || null,
      // Kept only as the id_token_hint for sign-out.
      idToken: tokens.id_token,
      user: userFromClaims(claims),
    });

    return this.safeReturnTo(pending.returnTo, pending.redirectUri);
  }

  /**
   * A page to return to after sign-in, when it is one of this WebUI's own
   * pages other than the login page; null otherwise.
   */
  safeReturnTo(returnTo, redirectUri) {
    if (!returnTo) return null;
    try {
      const url = new URL(returnTo, window.location.origin);
      const base = new URL(redirectUri);
      if (url.origin !== window.location.origin || !url.pathname.startsWith(base.pathname)) return null;
      const page = url.pathname.slice(base.pathname.length);
      if (page === '' || page === 'index.html') return null;
      return url.pathname + url.search + url.hash;
    } catch (e) {
      return null;
    }
  }

  // ============================================
  // Renewal
  // ============================================

  /**
   * Keep this page's SSO session alive: renew it in the background when the
   * provider issued a refresh token, otherwise warn before it ends and sign
   * in again when it does. Does nothing for a key-based session.
   */
  watch() {
    if (!this.session() || !api.credentials?.sessionToken) return;
    api.setCredentialRenewer(this);
    this._schedule();

    // Background tabs throttle timers, so look again when the tab returns.
    if (!this._watchingVisibility) {
      this._watchingVisibility = true;
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible' && this.session()) this._schedule();
      });
    }
  }

  /**
   * Called by api.js before signing: renew credentials that are about to
   * expire. Never throws; a session that cannot renew silently keeps its
   * credentials until they are rejected.
   */
  async beforeSign() {
    const expiration = api.credentials?.expiration;
    if (!expiration || expiration - Date.now() > SSO_SIGN_LEAD_MS) return;
    await this.renew();
  }

  /**
   * Called by api.js when the gateway rejected the credentials: renew them,
   * or failing that leave to sign in again.
   * @returns {boolean} True when fresh credentials are in place
   */
  async afterRejection() {
    if (await this.renew()) return true;
    this.reauthenticate();
    return false;
  }

  /**
   * Renew the credentials with the refresh token, if there is one. Concurrent
   * callers share one renewal.
   * @returns {Promise<boolean>} True when fresh credentials are in place
   */
  renew() {
    if (!this._renewing) {
      this._renewing = this._renew().finally(() => {
        this._renewing = null;
      });
    }
    return this._renewing;
  }

  async _renew() {
    const session = this.session();
    if (!session || !session.refreshToken) return false;

    try {
      const tokens = await this._tokenRequest(session.endpoints.token, {
        grant_type: 'refresh_token',
        refresh_token: session.refreshToken,
        client_id: session.config.clientId,
      });
      if (!tokens.id_token) {
        throw new SSOError('The identity provider\'s refresh response carried no ID token.');
      }
      const claims = decodeSSOJWT(tokens.id_token);
      const creds = await this._assumeRole(api.iamEndpoint, session.roleArn, tokens.id_token, claims, session.config);

      // Signed out while this was in flight: keep nothing.
      if (!this.session()) return false;
      // The endpoints stay as they are, and so do the capabilities detected
      // at sign-in: setCredentials() only clears the admin flag, which an
      // SSO session never has.
      this._useCredentials(creds, {
        region: api.region,
        s3Endpoint: api.s3Endpoint,
        addressingStyle: api.addressingStyle,
        iamEndpoint: api.iamEndpoint,
      });
      this._saveSession({
        ...session,
        refreshToken: tokens.refresh_token || session.refreshToken,
        idToken: tokens.id_token,
        user: userFromClaims(claims),
      });
    } catch (e) {
      console.warn('Single sign-on renewal failed:', e.message);
      const current = this.session();
      if (current) {
        // Fall back to warning before expiry and signing in again.
        this._saveSession({ ...current, refreshToken: null });
        this._schedule();
      }
      return false;
    }

    this._schedule();
    if (typeof updateUserInfo === 'function') updateUserInfo();
    return true;
  }

  _schedule() {
    clearTimeout(this._timer);
    const expiration = api.credentials?.expiration;
    const session = this.session();
    if (!expiration || !session) return;

    const untilLead = expiration - SSO_RENEW_LEAD_MS - Date.now();
    if (session.refreshToken) {
      this._hideBanner();
      this._timer = setTimeout(() => this.renew(), Math.max(0, untilLead));
      return;
    }
    if (untilLead <= 0) {
      this._showBanner();
    } else {
      this._timer = setTimeout(() => this._schedule(), untilLead);
    }
  }

  /**
   * Run the redirect flow again from any page, coming back to this one.
   */
  reauthenticate() {
    if (this._redirecting) return;
    const session = this.session();
    if (!session) {
      api.logout();
      window.location.href = 'index.html';
      return;
    }

    this._redirecting = true;
    this.begin({
      config: session.config,
      iamEndpoint: api.iamEndpoint,
      s3Endpoint: api.s3Endpoint,
      region: api.region,
      addressingStyle: api.addressingStyle,
      redirectUri: session.redirectUri,
      returnTo: window.location.pathname + window.location.search + window.location.hash,
      roleArn: session.roleArn,
    }).catch(e => {
      this._redirecting = false;
      if (typeof showToast === 'function') showToast(e.message, 'error');
    });
  }

  _showBanner() {
    let banner = document.getElementById('sso-session-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'sso-session-banner';
      banner.setAttribute('role', 'status');
      banner.className = 'fixed bottom-4 left-1/2 -translate-x-1/2 z-50 flex items-center gap-4 px-4 py-3 rounded-lg border-l-4 shadow-lg bg-yellow-50 border-yellow-500 text-yellow-800 text-sm';
      banner.innerHTML = '<span id="sso-session-banner-text"></span>' +
        '<button type="button" id="sso-session-banner-btn" class="px-3 py-1.5 bg-primary hover:bg-primary-600 text-white font-medium rounded-lg">Sign in again</button>';
      document.body.appendChild(banner);
      document.getElementById('sso-session-banner-btn').addEventListener('click', () => this.reauthenticate());
    }

    const tick = () => {
      const remaining = (api.credentials?.expiration || 0) - Date.now();
      if (remaining <= 0) {
        clearInterval(this._bannerTimer);
        document.getElementById('sso-session-banner-text').textContent = 'Session ended. Signing you in again…';
        this.reauthenticate();
        return;
      }
      const minutes = Math.ceil(remaining / 60000);
      document.getElementById('sso-session-banner-text').textContent =
        `Session ends in ${minutes} min${minutes === 1 ? '' : 's'}.`;
    };
    clearInterval(this._bannerTimer);
    tick();
    this._bannerTimer = setInterval(tick, 15000);
  }

  _hideBanner() {
    clearInterval(this._bannerTimer);
    document.getElementById('sso-session-banner')?.remove();
  }

  // ============================================
  // Sign-out
  // ============================================

  /**
   * The provider's end-session URL for the current session, or null when the
   * provider advertises none. Read it before api.logout() clears the session.
   */
  endSessionURL() {
    const session = this.session();
    if (!session || !session.endpoints?.endSession) return null;
    const url = new URL(session.endpoints.endSession);
    url.searchParams.set('client_id', session.config.clientId);
    url.searchParams.set('post_logout_redirect_uri', session.redirectUri);
    if (session.idToken) url.searchParams.set('id_token_hint', session.idToken);
    return url.toString();
  }

  // ============================================
  // Provider and STS calls
  // ============================================

  async _discover(issuer) {
    const url = issuer.replace(/\/+$/, '') + '/.well-known/openid-configuration';
    let response;
    try {
      response = await fetch(url);
    } catch (e) {
      throw new SSOError(`Cannot reach the identity provider at ${issuer}. Check that it is running and allows requests from ${window.location.origin} (CORS).`);
    }
    if (!response.ok) {
      throw new SSOError(`The identity provider's discovery document (${url}) returned HTTP ${response.status}. Check the issuer URL.`);
    }

    let doc;
    try {
      doc = await response.json();
    } catch (e) {
      throw new SSOError(`The identity provider's discovery document (${url}) is not valid JSON. Check the issuer URL.`);
    }
    if (doc.issuer !== issuer) {
      throw new SSOError(`The identity provider calls itself "${doc.issuer}", but the WebUI is configured with issuer "${issuer}". They must match exactly.`);
    }
    if (!doc.authorization_endpoint || !doc.token_endpoint) {
      throw new SSOError('The identity provider\'s discovery document lists no authorization or token endpoint.');
    }
    const methods = doc.code_challenge_methods_supported;
    if (Array.isArray(methods) && !methods.includes('S256')) {
      throw new SSOError('The identity provider does not support PKCE with S256, which WebUI sign-in requires.');
    }

    return {
      authorization: doc.authorization_endpoint,
      token: doc.token_endpoint,
      endSession: doc.end_session_endpoint || null,
    };
  }

  async _tokenRequest(tokenEndpoint, params) {
    let response;
    try {
      response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(params).toString(),
      });
    } catch (e) {
      throw new SSOError(`Cannot reach the identity provider's token endpoint. Check that the provider allows requests from ${window.location.origin} (web origins / CORS).`);
    }

    let body = {};
    try {
      body = await response.json();
    } catch (e) {
      // Reported below by status
    }
    if (!response.ok) {
      throw new SSOError(body.error_description || body.error || `The identity provider rejected the sign-in (HTTP ${response.status}).`, body.error || null);
    }
    return body;
  }

  /**
   * AssumeRoleWithWebIdentity, which needs no signature.
   */
  async _assumeRole(iamEndpoint, roleArn, idToken, claims, config) {
    const form = new URLSearchParams();
    form.set('Action', 'AssumeRoleWithWebIdentity');
    form.set('Version', STS_API_VERSION);
    form.set('RoleArn', roleArn);
    form.set('RoleSessionName', roleSessionName(claims));
    form.set('WebIdentityToken', idToken);
    if (config.sessionDuration) form.set('DurationSeconds', String(config.sessionDuration));

    let response;
    try {
      response = await fetch(iamEndpoint.replace(/\/+$/, '') + '/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      });
    } catch (e) {
      throw new SSOError(`Cannot reach the IAM service at ${iamEndpoint}. Check that it is running and allows requests from ${window.location.origin} (--cors-allow-origin).`);
    }

    const text = await response.text();
    const doc = new DOMParser().parseFromString(text, 'text/xml');
    if (!response.ok) {
      const code = parseXmlErrorCode(text);
      const message = doc.querySelector('Message')?.textContent || '';
      throw new SSOError(stsErrorMessage(code, message, claims), code);
    }

    const field = (name) => doc.querySelector(`Credentials > ${name}`)?.textContent || '';
    const creds = {
      accessKey: field('AccessKeyId'),
      secretKey: field('SecretAccessKey'),
      sessionToken: field('SessionToken'),
      expiration: Date.parse(field('Expiration')),
    };
    if (!creds.accessKey || !creds.secretKey || !creds.sessionToken || !creds.expiration) {
      throw new SSOError('The IAM service returned no credentials.');
    }
    return creds;
  }

  /**
   * The role ARNs a sign-in may use: those in the role claim, else the
   * configured role. A role kept from an earlier sign-in wins when it is
   * still among them.
   */
  _candidateRoles(claims, config, keepRoleArn) {
    let roles = config.roleClaim ? roleArnsFromClaim(claims[config.roleClaim]) : [];
    if (roles.length === 0 && config.roleArn) roles = [config.roleArn];
    if (roles.length === 0) {
      throw new SSOError('No role is assigned to your account. Ask your administrator.');
    }
    if (keepRoleArn && roles.includes(keepRoleArn)) return [keepRoleArn];
    return roles;
  }
}

/**
 * The user-facing message for an AssumeRoleWithWebIdentity error.
 */
function stsErrorMessage(code, message, claims) {
  const who = claims.email || claims.preferred_username || claims.sub || 'Your account';
  switch (code) {
    case 'AccessDenied':
      return `${who} isn't allowed to use this role. Ask your administrator.`;
    case 'InvalidIdentityToken':
      if (message.startsWith('Couldn\'t retrieve verification key')) {
        return 'The IAM service could not fetch the identity provider\'s signing keys. Check that it can reach the issuer, and its OIDC settings for a private or plain-http provider.';
      }
      if (message.startsWith('Missing a required claim')) {
        return `The gateway rejected the identity provider's token. ${message}`;
      }
      // The same answer covers a token failing the role's trust-policy
      // conditions and a provider or client ID the gateway doesn't trust.
      return 'Your sign-in was rejected: your account doesn\'t meet this role\'s conditions (for example, group membership), or the gateway doesn\'t trust this identity provider and client ID. Ask your administrator.';
    case 'ExpiredTokenException':
      return 'The identity provider\'s token had already expired when the gateway checked it. Check that the identity provider and the IAM service agree on the time.';
    case 'ValidationError':
      if (message.includes('MaxSessionDuration')) {
        return 'The single sign-on session duration is longer than this role allows. Ask your administrator.';
      }
      return message || 'The IAM service rejected the sign-in request.';
    default:
      return `${code || 'Error'}: ${message || 'the IAM service rejected the sign-in'}`;
  }
}

function roleArnsFromClaim(value) {
  const values = Array.isArray(value) ? value : (typeof value === 'string' ? [value] : []);
  const arns = values
    .filter(v => typeof v === 'string')
    .map(v => v.trim())
    .filter(v => SSO_ROLE_ARN_PATTERN.test(v));
  return [...new Set(arns)];
}

function roleNameFromArn(arn) {
  return String(arn || '').split('/').pop();
}

/**
 * RoleSessionName from the token: email, else preferred_username, else sub,
 * reduced to the characters and length STS accepts.
 */
function roleSessionName(claims) {
  const raw = claims.email || claims.preferred_username || claims.sub || '';
  const name = String(raw).replace(/[^\w+=,.@-]/g, '').slice(0, 64);
  return name.length >= 2 ? name : SSO_SESSION_NAME_FALLBACK;
}

function userFromClaims(claims) {
  const pick = (key) => (typeof claims[key] === 'string' ? claims[key] : undefined);
  return {
    email: pick('email'),
    name: pick('name'),
    preferred_username: pick('preferred_username'),
    sub: pick('sub'),
  };
}

/**
 * The payload of a JWT. Its signature is not checked here: the IAM service
 * verifies it, and the token came straight from the provider over TLS.
 */
function decodeSSOJWT(token) {
  try {
    const payload = token.split('.')[1];
    const binary = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    throw new SSOError('The identity provider returned a malformed ID token.');
  }
}

function randomSSOToken(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = '';
  bytes.forEach(b => {
    binary += String.fromCharCode(b);
  });
  return base64ToBase64url(btoa(binary));
}

function base64ToBase64url(value) {
  return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function readSSOJSON(key) {
  try {
    return JSON.parse(sessionStorage.getItem(key) || 'null');
  } catch (e) {
    return null;
  }
}

const sso = new VersitySSO();
