# ubik-kit

Client SDK for apps that use **Ubik** for licensing. It lets a desktop/native app
sign the user in through their browser (Authorization Code + PKCE, loopback
redirect), read the user's licenses for its product, activate devices and verify
device tokens offline. The app never handles the user's Ubik credentials.

## Install

```bash
npm install github:ubikee/ubik-kit
```

## Two ways to activate

Every app that uses Ubik must offer both on its license screen:

1. **Connect with Ubik** — `connect()`: the user signs in through the browser and
   one of their licenses for this product is activated on this device.
2. **Paste a key** — `activate()`: the user types the license key by hand.

```js
import { activate, connect, fingerprintFromHost } from 'ubik-kit';

const baseUrl = 'https://market.ubikee.com';
const fingerprint = fingerprintFromHost();

// 1. "Connect with Ubik" button
const { license, activation } = await connect({
  baseUrl,
  clientId: 'deep-scout', // the product slug
  fingerprint,
  label: 'MacBook de Ana',
  version: '1.4.0',
  // Only called with several usable licenses; return one of them, or nothing to cancel.
  pick: async (licenses) => askTheUser(licenses),
});

// 2. "Paste your key" field
const manual = await activate({ baseUrl, licenseKey: typedKey, fingerprint, label: 'MacBook de Ana' });
```

`connect()` skips revoked and expired licenses, uses the only one without asking,
and checks that the owner signed into the device token (`usr`) is the user who
signed in. Errors carry a `code`: `access_denied` (the user said no in Ubik),
`login_timeout`, `no_license` (show a link to buy it), `license_not_selected`
(the user cancelled the pick) or `owner_mismatch`; Ubik errors such as
`activation_limit_reached` come through unchanged.

## Login

```js
import { login, getLicenses } from 'ubik-kit';

const session = await login({
  baseUrl: 'https://ubik.example.com',
  clientId: 'deep-scout', // the product slug
  scopes: ['licenses:read'],
});

const { licenses } = await getLicenses({
  baseUrl: 'https://ubik.example.com',
  accessToken: session.accessToken,
});
```

`login()` starts a temporary HTTP server on `127.0.0.1`, opens the system browser
at `/oauth/authorize`, waits for the callback, and exchanges the one-time code
(proving PKCE) for a short-lived, product-scoped access token. Pass
`openBrowser: (url) => ...` to control how the browser is opened, or
`onReady({ authorizeUrl })` if you want to surface the URL yourself.

## Activation and offline verification

```js
import { activate, heartbeat, fetchJwks, verifyOffline } from 'ubik-kit';

const activation = await activate({
  baseUrl: 'https://ubik.example.com',
  licenseKey: licenses[0].licenseKey,
  fingerprint: { os: 'macos', machineId: '...' }, // object or string
  label: 'MacBook de Ana',
  version: '1.4.0',
});

const jwks = await fetchJwks({ baseUrl: 'https://ubik.example.com' });
const verified = verifyOffline({ token: activation.token, keys: jwks });
// verified.payload -> { lic, usr, plan, seats, exp, ... }
```

The device token is an Ed25519 compact JWS. Cache the JWKS and verify offline;
call `heartbeat()` when online to renew it.

## API

- `connect({ baseUrl, clientId, fingerprint, label, version, pick, openBrowser, onReady, timeoutMs })` → `{ license, activation }`
- `usableLicenses(licenses)` → the issued/active, unexpired ones
- `createPkce()` → `{ verifier, challenge }`
- `login({ baseUrl, clientId, scopes, openBrowser, onReady, timeoutMs })`
- `getLicenses({ baseUrl, accessToken })`
- `activate({ baseUrl, licenseKey, fingerprint, label, version })`
- `heartbeat({ baseUrl, deviceToken, fingerprint, version })`
- `deactivate({ baseUrl, deviceToken })` → frees this device's seat ("deactivate this computer")
- `report({ baseUrl, deviceToken, licenseKey, fingerprint, code, message, details })`
- `fetchJwks({ baseUrl })`
- `verifyDeviceToken(token, keys)` / `verifyOffline({ baseUrl, token, keys })`
- `openUrl(url)`
