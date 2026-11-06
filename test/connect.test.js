import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { connect, deactivate, usableLicenses } from '../src/index.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const fakeToken = (payload) => `${b64({ alg: 'EdDSA', kid: 'k' })}.${b64(payload)}.sig`;

const license = (id, overrides = {}) => ({
  id,
  userId: 42,
  licenseKey: `UBIK-AAAA-BBBB-CCCC-000${id}`,
  status: 'issued',
  expiresAt: null,
  ...overrides,
});

/**
 * Minimal Ubik: OAuth token exchange (checks PKCE), the user's licenses and
 * machine activation. `tokenOwner` lets a test forge a mismatched `usr`.
 */
async function startFakeUbik({ licenses, tokenOwner = (lic) => lic.userId }) {
  const codes = new Map();
  const activated = [];
  const server = http.createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : {};
    const send = (status, data) => res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(data));

    if (req.url === '/api/oauth/token') {
      const entry = codes.get(body.code);
      const challenge = crypto.createHash('sha256').update(String(body.code_verifier)).digest('base64url');
      if (!entry || entry.challenge !== challenge || entry.redirectUri !== body.redirect_uri) {
        return send(400, { error: { code: 'invalid_grant', message: 'Invalid code' } });
      }
      return send(200, { access_token: 'oauth-token', token_type: 'Bearer', expires_in: 3600, scope: 'licenses:read' });
    }
    if (req.url === '/api/oauth/licenses') {
      if (req.headers.authorization !== 'Bearer oauth-token') return send(401, { error: { code: 'unauthorized' } });
      return send(200, { productId: 1, licenses });
    }
    if (req.url === '/api/activation/deactivate') {
      if (req.headers.authorization !== 'Bearer device-token') return send(401, { error: { code: 'invalid_device_token' } });
      return send(200, { activation: { id: 1, status: 'deactivated' }, license: { id: 1, activationsCount: 0 } });
    }
    if (req.url === '/api/activation/activate') {
      const lic = licenses.find((item) => item.licenseKey === body.licenseKey);
      if (!lic) return send(404, { error: { code: 'license_not_found', message: 'License not found' } });
      activated.push({ licenseKey: body.licenseKey, fingerprint: body.fingerprint, label: body.label });
      return send(200, {
        token: fakeToken({ lic: lic.id, usr: tokenOwner(lic) }),
        license: { id: lic.id, userId: lic.userId, status: 'active' },
        activation: { id: activated.length, deviceId: 'fp_123' },
      });
    }
    send(404, { error: { code: 'not_found' } });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  // Plays the browser + consent screen: issues a code and follows the loopback redirect.
  const openBrowser = async (url) => {
    const params = new URL(url).searchParams;
    const code = crypto.randomBytes(8).toString('hex');
    codes.set(code, { challenge: params.get('code_challenge'), redirectUri: params.get('redirect_uri') });
    const callback = new URL(params.get('redirect_uri'));
    callback.searchParams.set('code', code);
    callback.searchParams.set('state', params.get('state'));
    await fetch(callback);
  };

  return { baseUrl, openBrowser, activated, close: () => new Promise((resolve) => server.close(resolve)) };
}

const options = (ubik, extra = {}) => ({
  baseUrl: ubik.baseUrl,
  clientId: 'acme',
  openBrowser: ubik.openBrowser,
  fingerprint: { machineId: 'm-1' },
  label: 'Laptop',
  ...extra,
});

test('usableLicenses keeps issued/active licenses that have not expired', () => {
  const now = Date.now();
  const list = [
    license(1),
    license(2, { status: 'active', expiresAt: new Date(now + DAY_MS).toISOString() }),
    license(3, { status: 'revoked' }),
    license(4, { status: 'expired' }),
    license(5, { expiresAt: new Date(now - 1000).toISOString() }),
  ];
  assert.deepEqual(usableLicenses(list, { now }).map((item) => item.id), [1, 2]);
  assert.deepEqual(usableLicenses(undefined), []);
});

test('connect signs in and activates the only usable license without asking', async () => {
  const ubik = await startFakeUbik({ licenses: [license(1), license(2, { status: 'revoked' })] });
  try {
    let asked = false;
    const result = await connect(options(ubik, { pick: () => (asked = true) }));
    assert.equal(asked, false);
    assert.equal(result.license.id, 1);
    assert.equal(result.activation.license.status, 'active');
    assert.deepEqual(ubik.activated, [
      { licenseKey: 'UBIK-AAAA-BBBB-CCCC-0001', fingerprint: { machineId: 'm-1' }, label: 'Laptop' },
    ]);
  } finally {
    await ubik.close();
  }
});

test('connect lets the app pick among several licenses, defaulting to the most recent', async () => {
  const ubik = await startFakeUbik({ licenses: [license(3), license(2), license(1)] });
  try {
    let offered;
    const picked = await connect(
      options(ubik, {
        pick: (licenses) => {
          offered = licenses.map((item) => item.id);
          return licenses[2];
        },
      })
    );
    assert.deepEqual(offered, [3, 2, 1]);
    assert.equal(picked.license.id, 1);

    const byDefault = await connect(options(ubik));
    assert.equal(byDefault.license.id, 3);
  } finally {
    await ubik.close();
  }
});

test('connect fails clearly when there is nothing to activate or the pick is cancelled', async () => {
  const empty = await startFakeUbik({ licenses: [license(1, { status: 'expired' })] });
  try {
    await assert.rejects(connect(options(empty)), { code: 'no_license' });
    assert.equal(empty.activated.length, 0);
  } finally {
    await empty.close();
  }

  const several = await startFakeUbik({ licenses: [license(1), license(2)] });
  try {
    await assert.rejects(connect(options(several, { pick: () => null })), { code: 'license_not_selected' });
    await assert.rejects(connect(options(several, { pick: () => license(9) })), { code: 'license_not_selected' });
    assert.equal(several.activated.length, 0);
  } finally {
    await several.close();
  }
});

test('connect rejects a device token whose owner is not the signed-in user', async () => {
  const ubik = await startFakeUbik({ licenses: [license(1)], tokenOwner: () => 7 });
  try {
    await assert.rejects(connect(options(ubik)), { code: 'owner_mismatch' });
  } finally {
    await ubik.close();
  }
});

test('deactivate gives the seat back with the device token', async () => {
  const ubik = await startFakeUbik({ licenses: [] });
  try {
    const freed = await deactivate({ baseUrl: ubik.baseUrl, deviceToken: 'device-token' });
    assert.equal(freed.activation.status, 'deactivated');
    await assert.rejects(deactivate({ baseUrl: ubik.baseUrl, deviceToken: 'forged' }), {
      status: 401,
      code: 'invalid_device_token',
    });
  } finally {
    await ubik.close();
  }
});
