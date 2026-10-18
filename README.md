# ubik-kit

Client SDK for apps that use **Ubik** for licensing. It lets a desktop/native app
sign the user in through their browser (Authorization Code + PKCE, loopback
redirect), read the user's licenses for its product, activate devices and verify
device tokens offline. The app never handles the user's Ubik credentials.

## Install

```bash
npm install github:ubikee/ubik-kit
```

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
// verified.payload -> { lic, plan, seats, exp, ... }
```

The device token is an Ed25519 compact JWS. Cache the JWKS and verify offline;
call `heartbeat()` when online to renew it.

## API

- `createPkce()` → `{ verifier, challenge }`
- `login({ baseUrl, clientId, scopes, openBrowser, onReady, timeoutMs })`
- `getLicenses({ baseUrl, accessToken })`
- `activate({ baseUrl, licenseKey, fingerprint, label, version })`
- `heartbeat({ baseUrl, deviceToken, fingerprint, version })`
- `report({ baseUrl, deviceToken, licenseKey, fingerprint, code, message, details })`
- `fetchJwks({ baseUrl })`
- `verifyDeviceToken(token, keys)` / `verifyOffline({ baseUrl, token, keys })`
- `openUrl(url)`
