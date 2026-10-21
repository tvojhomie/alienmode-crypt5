# AlienMode crypt5

[Русская инструкция](README.ru.md) · [API schema](openapi.json) · [Wire format](PROTOCOL.md) · [MIT license](LICENSE)

Generate `alienmode://crypt5/…` subscription links on your own server. Includes an
ES-module library, stdin CLI, and authenticated self-hosted HTTP API. Node.js 22+
is required. No third-party runtime dependencies or external encryption service.

Opening a link in **AlienMode build 22+** imports and refreshes the subscription.
The client must be installed; this repository does not include an installer.
This is AlienMode's own format, **not Happ crypt5**.

## Quick start

Clone or download this repository, then enter its directory. No `npm install` is
needed to run the CLI or API.

Create a private `request.json` file (0600 permissions) containing:

```json
{"url":"https://vpn.example/sub/personal-token","title":"My VPN"}
```

```sh
node cli.mjs < request.json > link.json
```

The result is `{"link":"alienmode://crypt5/am-2026-01.…"}`. Use the link in a QR
code or an HTML link/button. Escape HTML attributes correctly. Do not put real
subscription URLs in shell arguments, public issues, examples, or logs.

## Library integration

Copy the module files together with `recipient.json`, or install this repository
as a Git dependency. The package exports `encryptLink`:

```js
import { encryptLink } from './index.mjs';
const link = encryptLink({ url: subscription.httpsURL, title: 'My VPN' });
```

When installed as a dependency, import from `@alienmode/crypt5` instead.
This package has not been published to the npm registry.

- `url`: HTTPS only, no userinfo, at most 16384 UTF-8 bytes.
- `title`: optional, at most 200 Unicode code points, no control characters.
- Each invocation generates a new ephemeral key and nonce. The client
  deduplicates by the decrypted subscription URL.
- The generator does not fetch the subscription or contact AlienMode or Happ.

## Provider API

Create a random API token in a file outside your web root:

```sh
umask 077
node --input-type=module -e "import {randomBytes} from 'node:crypto'; process.stdout.write(randomBytes(32).toString('base64url'))" > api-token
ALIENMODE_API_TOKEN_FILE="$PWD/api-token" PORT=8787 node server.mjs
```

The service binds to **127.0.0.1 only**. For remote use, configure your domain and
an HTTPS reverse proxy. Example Caddy configuration:

```caddyfile
links.your-provider.example {
    log {
        output discard
    }
    reverse_proxy 127.0.0.1:8787
}
```

```http
POST /v1/links
Authorization: Bearer <provider-api-token>
Content-Type: application/json

{"url":"https://vpn.example/sub/personal-token","title":"My VPN"}
```

Success: HTTP 200 with a `link` field. Errors: 400 invalid input, 401 unauthorized,
404 unsupported path/method, 413 oversized body, 415 unsupported content type,
429 rate limit. See [OpenAPI](openapi.json).

Limits: 24 KiB request body, 15-second request timeout, 120 authenticated requests
per minute per process. Responses use `Cache-Control: no-store`; CORS is not enabled.
The API does not log request bodies, authorization headers, or generated links.
Disable these logs in your proxy/APM too. Keep the token on your backend, never in
browser code or QR codes. Use separate instances/tokens or your own auth gateway
for multiple providers. The example API is not a hosted public service.

## Security and compatibility

Uses X25519, HKDF-SHA256 and ChaCha20-Poly1305. This SDK contains only the
recipient **public key**; it does not contain the client decryption key.

The client necessarily has a shared decryption key. The format hides a URL from
casual inspection, but does not protect it from someone analyzing the client.
Encrypted links are still transferable access secrets. Enforce expiration,
revocation, device limits, and subscription authorization on your own backend.
Anyone with the public key can generate a link: this is **not provider identity
verification** or a provider signature. No independent security audit has been performed.

Do not change the public key under an existing `kid`. Rotation requires a new
key identifier and a client update before providers start issuing links with it.

## Tests

```sh
node --test test/api.test.mjs
```

Tests cover encryption envelopes, validation, CLI behavior, authentication, limits,
and actual loopback HTTP requests using synthetic data. Node → Swift CryptoKit
compatibility is tested separately in the AlienMode client project.

## License

MIT. Commercial use, modification and integration are permitted under [LICENSE](LICENSE).
