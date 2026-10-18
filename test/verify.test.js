import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  DEFAULT_GRACE_DAYS,
  evaluateDeviceToken,
  fingerprintFromHost,
  verifyDeviceToken,
} from '../src/index.js';

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const nowSeconds = () => Math.floor(Date.now() / 1000);

function signJws(payload, { kid, privateKey }) {
  const input = `${b64({ alg: 'EdDSA', typ: 'JWT', kid })}.${b64(payload)}`;
  const signature = crypto.sign(null, Buffer.from(input, 'utf8'), privateKey).toString('base64url');
  return `${input}.${signature}`;
}

function makeKey(kid = 'key-1') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig' };
  return { privateKey, jwk };
}

const payload = (overrides = {}) => {
  const iat = nowSeconds();
  return { iss: 'ubik', lic: 7, plan: 3, seats: 2, hb: 86400, graceDays: DEFAULT_GRACE_DAYS, iat, exp: iat + 3600, ...overrides };
};

test('verifies a signed device token with an array or a kid map', () => {
  const { privateKey, jwk } = makeKey();
  const token = signJws(payload(), { kid: jwk.kid, privateKey });

  assert.equal(verifyDeviceToken(token, [jwk])?.payload.lic, 7);
  assert.equal(verifyDeviceToken(token, { [jwk.kid]: jwk })?.payload.lic, 7);
});

test('rejects tampered tokens and unknown keys', () => {
  const { privateKey, jwk } = makeKey();
  const token = signJws(payload(), { kid: jwk.kid, privateKey });
  const [header, , signature] = token.split('.');
  const tampered = `${header}.${b64(payload({ seats: 999 }))}.${signature}`;

  assert.equal(verifyDeviceToken(tampered, [jwk]), null);
  assert.equal(verifyDeviceToken(token, [makeKey('other').jwk]), null);
  assert.equal(verifyDeviceToken('not-a-jws', [jwk]), null);
});

test('classifies the offline policy: online_ok, warn, grace and blocked', () => {
  const { privateKey, jwk } = makeKey();
  const start = Date.UTC(2026, 0, 1, 12, 0, 0);
  const startSeconds = Math.floor(start / 1000);
  const token = signJws(payload({ iat: startSeconds, exp: startSeconds + 3600 }), { kid: jwk.kid, privateKey });

  // Before expiry.
  assert.equal(evaluateDeviceToken(token, [jwk], { now: start }).tier, 'online_ok');

  // Heartbeat overdue -> warn.
  const stale = new Date(start - 3 * 24 * 60 * 60 * 1000).toISOString();
  assert.equal(evaluateDeviceToken(token, [jwk], { now: start, lastHeartbeatAt: stale }).tier, 'warn');

  // Expired but inside grace -> grace.
  const withinGrace = start + 3600 * 1000 + 5 * 24 * 60 * 60 * 1000;
  assert.equal(evaluateDeviceToken(token, [jwk], { now: withinGrace }).tier, 'grace');

  // Beyond grace -> blocked.
  const beyond = start + 3600 * 1000 + (DEFAULT_GRACE_DAYS + 1) * 24 * 60 * 60 * 1000;
  const blocked = evaluateDeviceToken(token, [jwk], { now: beyond });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.tier, 'blocked');
  assert.equal(blocked.reason, 'token_expired_beyond_grace');
});

test('a signed token without exp is rejected as invalid', () => {
  const { privateKey, jwk } = makeKey();
  const { exp, ...withoutExp } = payload();
  const token = signJws(withoutExp, { kid: jwk.kid, privateKey });

  const result = evaluateDeviceToken(token, [jwk]);
  assert.equal(result.ok, false);
  assert.equal(result.tier, 'blocked');
  assert.equal(result.reason, 'invalid_payload');
});

test('fingerprintFromHost is deterministic and honours overrides', () => {
  const base = fingerprintFromHost();
  assert.ok(base.machineId);
  assert.deepEqual(fingerprintFromHost({ machineId: 'abc' }), { ...base, machineId: 'abc' });
});
