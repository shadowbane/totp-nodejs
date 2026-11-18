# Tick

Free TOTP (two-factor) codes in your browser. Part of [DevHelper](https://devhelper.my.id).

**Live:** <https://totp.devhelper.my.id>

Paste a secret key or an `otpauth://` link and get the current code. Long keys work. Nothing you type leaves the page.

## Features

- RFC 6238 TOTP with SHA-1, SHA-256 or SHA-512, 6–8 digits and any period from 5 to 300 seconds.
- Long and messy keys: spaces, dashes, lowercase and padding are fine.
- Paste an `otpauth://totp/...` link to fill in every field.
- QR code for adding a key to an authenticator app.
- Optional encrypted vault for saved keys, with encrypted backup export and import.
- Light and dark themes.

## Privacy and security

- Codes are made with the browser's Web Crypto API. Secret keys are never sent anywhere.
- The site's Content Security Policy blocks all network connections after the page loads. Fonts and scripts are served from the same origin.
- Saved keys are encrypted with a key derived from your passphrase (PBKDF2-SHA256, 600,000 rounds), using AES-256-GCM with a fresh IV on every write. The derived key is non-extractable and kept only in memory. The vault locks after 5 minutes idle.
- The vault protects keys at rest. It does not protect against malware or a compromised browser. A forgotten passphrase cannot be recovered.

See the [terms](https://totp.devhelper.my.id/terms) and [privacy](https://totp.devhelper.my.id/privacy) pages. Tick is provided as is, with no warranty and no support.

## Repository layout

| Path | What it is |
| --- | --- |
| `web/` | Tick, the web app (Vite, React, TypeScript, Tailwind). |
| `web/src/lib/` | TOTP, base32, otpauth, vault and legacy-migration logic, with tests. |
| `web/public/_headers` | CSP and security headers. |
| `published/` | The old single-file page. Kept for reference; not deployed by the new setup. |
| `index.js` | A small Node CLI demo that prints a TOTP code and a QR code in the terminal. |

## Development

Requires Node 20+ and pnpm.

```sh
cd web
pnpm install
pnpm dev        # http://localhost:5195
pnpm test       # unit tests
pnpm build      # type-check and build to web/dist
```

## Deploy

Tick is served by Cloudflare Workers static assets (`web/wrangler.toml`, Worker `totp-nodejs`). The Worker is connected to this repo with Workers Builds, so every push to `master` deploys. Its build settings:

| Setting | Value |
| --- | --- |
| Root directory | `web` |
| Build command | `pnpm install --frozen-lockfile && pnpm build` |
| Deploy command | `npx wrangler deploy` |

To deploy by hand instead: `cd web && pnpm build && npx wrangler deploy`.

`_headers` only takes effect on Cloudflare. `vite preview` does not apply it, so test the CSP with `npx wrangler dev` after a build.

## Contributing

Issues and pull requests are welcome. There is no support and no guaranteed reply.

## License

[MIT](LICENSE)
