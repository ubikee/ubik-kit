import crypto from 'node:crypto';
import http from 'node:http';
import os from 'node:os';
import { spawn } from 'node:child_process';

export const DEFAULT_HEARTBEAT_SECONDS = 24 * 60 * 60;
export const DEFAULT_GRACE_DAYS = 30;

const normalizeBase = (baseUrl) => String(baseUrl ?? '').replace(/\/+$/, '');
const keysArray = (keys) => (Array.isArray(keys) ? keys : Object.values(keys ?? {}));

/** Best-effort device fingerprint from host information; overrides win. */
export function fingerprintFromHost(overrides = {}) {
  const [cpu] = os.cpus();
  const fingerprint = { machineId: [os.hostname(), os.platform(), os.arch()].join('-') };
  if (cpu?.model) fingerprint.cpuId = cpu.model;
  return { ...fingerprint, ...overrides };
}

/** Generates a PKCE verifier/challenge pair (S256). */
export function createPkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/** Opens a URL in the user's default browser (macOS, Windows, Linux). */
export function openUrl(url) {
  const [command, args] =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? ['cmd', ['/c', 'start', '', url]]
        : ['xdg-open', [url]];
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'ignore', detached: true });
    child.once('error', reject);
    child.once('spawn', () => {
      child.unref();
      resolve();
    });
  });
}

async function request(url, { method = 'GET', token, body, timeoutMs = 10_000 } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const error = new Error(data?.error?.message || `Ubik responded with ${res.status}`);
    error.status = res.status;
    error.code = data?.error?.code;
    throw error;
  }
  return data;
}

/**
 * Opens the browser so the user signs in to Ubik, then returns a scoped token.
 * The app never sees the user's credentials.
 *
 * @returns {Promise<{accessToken: string, tokenType: string, expiresIn: number, scope: string, clientId: string}>}
 */
export async function login({
  baseUrl,
  clientId,
  scopes = ['licenses:read'],
  openBrowser = openUrl,
  timeoutMs = 5 * 60 * 1000,
  redirectPath = '/callback',
  onReady,
} = {}) {
  if (!baseUrl) throw new Error('ubik-kit: baseUrl is required');
  if (!clientId) throw new Error('ubik-kit: clientId is required');

  const base = normalizeBase(baseUrl);
  const { verifier, challenge } = createPkce();
  const state = crypto.randomBytes(16).toString('base64url');

  const server = http.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  const redirectUri = `http://127.0.0.1:${port}${redirectPath}`;

  const authorizeUrl = new URL(`${base}/oauth/authorize`);
  authorizeUrl.searchParams.set('client_id', clientId);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', scopes.join(' '));
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  let timer;
  const closeServer = () => {
    clearTimeout(timer);
    server.close();
  };

  const codePromise = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      closeServer();
      reject(new Error('ubik-kit: timed out waiting for the browser'));
    }, timeoutMs);

    server.on('request', (req, res) => {
      const url = new URL(req.url, redirectUri);
      if (req.method !== 'GET' || url.pathname !== redirectPath) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><meta charset="utf-8"><title>Ubik</title><p>Ya puedes volver a la aplicación.</p>');
      closeServer();

      const error = url.searchParams.get('error');
      if (error) return reject(new Error(`ubik-kit: authorization failed (${error})`));
      if (url.searchParams.get('state') !== state) return reject(new Error('ubik-kit: state mismatch'));
      const code = url.searchParams.get('code');
      if (!code) return reject(new Error('ubik-kit: missing authorization code'));
      resolve(code);
    });
  });

  onReady?.({ authorizeUrl: authorizeUrl.toString(), redirectUri });
  try {
    await openBrowser(authorizeUrl.toString());
  } catch (err) {
    closeServer();
    codePromise.catch(() => {});
    throw err;
  }

  const code = await codePromise;
  const data = await request(`${base}/api/oauth/token`, {
    method: 'POST',
    body: {
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    },
  });
  return {
    accessToken: data.access_token,
    tokenType: data.token_type,
    expiresIn: data.expires_in,
    scope: data.scope,
    clientId,
  };
}

/** Reads the signed-in user's licenses for the product bound to the token. */
export function getLicenses({ baseUrl, accessToken }) {
  return request(`${normalizeBase(baseUrl)}/api/oauth/licenses`, { token: accessToken });
}

const USABLE_STATUSES = ['issued', 'active'];

function kitError(code, message) {
  const error = new Error(`ubik-kit: ${message}`);
  error.code = code;
  return error;
}

/** Reads a JWS payload without verifying it (verification happens offline with the JWKS). */
function decodePayload(token) {
  try {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

/** Licenses that can still be activated: issued or active and not past their expiry. */
export function usableLicenses(licenses, { now = Date.now() } = {}) {
  return (licenses ?? []).filter(
    (license) =>
      USABLE_STATUSES.includes(license.status) && (!license.expiresAt || Date.parse(license.expiresAt) > now)
  );
}

/**
 * "Connect with Ubik": the user signs in through the browser, one of their
 * usable licenses for this product is chosen and activated on this device.
 * With several licenses `pick(licenses)` decides (default: the most recent);
 * returning nothing cancels. The manual alternative is `activate()` with a
 * key the user pastes.
 *
 * @returns {Promise<{license: object, activation: object}>}
 */
export async function connect({
  baseUrl,
  clientId,
  fingerprint = fingerprintFromHost(),
  label,
  version,
  pick,
  openBrowser,
  onReady,
  timeoutMs,
} = {}) {
  const session = await login({ baseUrl, clientId, openBrowser, onReady, timeoutMs });
  const { licenses } = await getLicenses({ baseUrl, accessToken: session.accessToken });

  const usable = usableLicenses(licenses);
  if (usable.length === 0) throw kitError('no_license', 'no usable license for this product');
  const license = usable.length === 1 || !pick ? usable[0] : await pick(usable);
  if (!license) throw kitError('license_not_selected', 'no license was selected');
  if (!usable.includes(license)) throw kitError('license_not_selected', 'pick() must return one of the given licenses');

  const activation = await activate({ baseUrl, licenseKey: license.licenseKey, fingerprint, label, version });
  if (decodePayload(activation.token)?.usr !== license.userId) {
    throw kitError('owner_mismatch', 'the device token does not belong to the signed-in user');
  }
  return { license, activation };
}

/** Activates a license key on a device; returns a signed device token. */
export function activate({ baseUrl, licenseKey, fingerprint, label, version }) {
  return request(`${normalizeBase(baseUrl)}/api/activation/activate`, {
    method: 'POST',
    body: { licenseKey, fingerprint, label, version },
  });
}

/** Renews a device token and returns a fresh one. */
export function heartbeat({ baseUrl, deviceToken, fingerprint, version }) {
  return request(`${normalizeBase(baseUrl)}/api/activation/heartbeat`, {
    method: 'POST',
    token: deviceToken,
    body: { fingerprint, version },
  });
}

/** Sends a fire-and-forget incident report (device token and/or license key). */
export function report({ baseUrl, deviceToken, licenseKey, fingerprint, code, message, details }) {
  return request(`${normalizeBase(baseUrl)}/api/activation/report`, {
    method: 'POST',
    token: deviceToken,
    body: { licenseKey, fingerprint, code, message, details },
  });
}

/** Fetches the public JWKS used to verify device tokens offline. */
export async function fetchJwks({ baseUrl }) {
  const data = await request(`${normalizeBase(baseUrl)}/api/activation/jwks.json`);
  return data.keys;
}

/** Verifies an Ed25519 device token against a JWKS list or kid->JWK map. */
export function verifyDeviceToken(token, keys) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerPart, payloadPart, signaturePart] = parts;

  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!header || header.alg !== 'EdDSA' || !payload || typeof payload !== 'object') return null;

  const jwk = keysArray(keys).find((key) => key.kid === header.kid);
  if (!jwk) return null;

  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    return null;
  }
  const signature = Buffer.from(signaturePart, 'base64url');
  const ok = crypto.verify(null, Buffer.from(`${headerPart}.${payloadPart}`, 'utf8'), publicKey, signature);
  return ok ? { header, payload } : null;
}

/**
 * Offline lifecycle policy. Verifies the signature, then classifies the token
 * as `online_ok`, `warn` (heartbeat overdue), `grace` (expired within grace) or
 * `blocked`. `lastHeartbeatAt` is optional (ISO string from the app's state).
 */
export function evaluateDeviceToken(token, keys, { now = Date.now(), lastHeartbeatAt = null } = {}) {
  const verified = verifyDeviceToken(token, keys);
  if (!verified) return { ok: false, tier: 'blocked', reason: 'invalid_token', payload: null };

  const { payload } = verified;
  if (!Number.isFinite(payload.exp)) return { ok: false, tier: 'blocked', reason: 'invalid_payload', payload };
  const nowSeconds = Math.floor(now / 1000);
  const graceDays = Number.isFinite(payload.graceDays) ? payload.graceDays : DEFAULT_GRACE_DAYS;
  const overdueSeconds = nowSeconds - payload.exp;

  let tier = 'online_ok';
  let reason = null;
  if (overdueSeconds > 0) {
    if (overdueSeconds <= graceDays * 24 * 60 * 60) {
      tier = 'grace';
    } else {
      tier = 'blocked';
      reason = 'token_expired_beyond_grace';
    }
  }

  if (tier === 'online_ok' && lastHeartbeatAt) {
    const heartbeatSeconds = payload.hb || DEFAULT_HEARTBEAT_SECONDS;
    const ageSeconds = (now - Date.parse(lastHeartbeatAt)) / 1000;
    if (Number.isFinite(ageSeconds) && ageSeconds > heartbeatSeconds) tier = 'warn';
  }

  return { ok: tier !== 'blocked', tier, reason, payload };
}

/** Convenience: fetch JWKS (unless provided) and verify a device token offline. */
export async function verifyOffline({ baseUrl, token, keys }) {
  const jwks = keys ?? (await fetchJwks({ baseUrl }));
  return verifyDeviceToken(token, jwks);
}
