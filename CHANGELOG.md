# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-11-18

### Added

- A card between the intro and the generator recommends our partner ZapYap, a zero-knowledge password manager and authenticator that works across devices.
- The privacy page explains the ZapYap link and its `utm` tags.

### Changed

- Pages are served with `Cache-Control: no-transform`, so Cloudflare does not inject its Web Analytics script, which the CSP would block.

## [1.0.0] - 2026-11-18

First versioned release. The web tool is renamed **Tick** and joins the DevHelper suite. It stays at <https://totp.devhelper.my.id>.

### Added

- New web app in `web/` (Vite, React, TypeScript, Tailwind) in the DevHelper design, with light and dark themes.
- Long secret keys: the secret field wraps and grows. Spaces, dashes, lowercase and `=` padding are accepted, and keys of any length decode.
- Pasting an `otpauth://totp/` link fills in the secret, issuer, account, algorithm, digits and period.
- Clear errors for invalid characters, with a hint for look-alike digits (for example `0` where the letter `O` was meant).
- The next code is shown under the current one, with a countdown ring.
- Encrypted vault for saved keys: PBKDF2-SHA256 (600,000 rounds) and AES-256-GCM, with the key held in memory only. It locks after 5 minutes idle and when another tab changes it.
- Encrypted backup export and import.
- Saved keys show live codes, with copy and open actions.
- The QR code is drawn as SVG, hidden until asked for, with a "Copy otpauth link" button.
- Terms of use and privacy pages (`/terms`, `/privacy`).
- Strict Content Security Policy and security headers (`web/public/_headers`). The page cannot connect to any server after it loads.
- Unit tests (Vitest): RFC 6238 and RFC 4226 vectors, base32, otpauth parsing, vault and legacy migration.
- MIT `LICENSE`, `README.md` and this changelog.

### Changed

- The default algorithm is SHA-1, the TOTP standard that most sites and authenticator apps use. The old default was SHA-256, which Google Authenticator ignores. Migrated keys keep their own algorithm.
- Digits are limited to 6, 7 or 8, and the period to 5–300 seconds.
- Fonts and scripts are bundled with the app. Nothing is loaded from a CDN.
- Keys typed into the generator are no longer saved automatically.

### Removed

- Plaintext storage of secrets in `localStorage`. On first vault create or unlock, keys saved by the old page (`totp_saved_configs` and `totp_*`) move into the encrypted vault, and the plaintext copies are deleted.

### Security

- Saved secrets are encrypted at rest. A forgotten passphrase cannot be recovered.

[Unreleased]: https://github.com/shadowbane/totp-nodejs/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/shadowbane/totp-nodejs/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/shadowbane/totp-nodejs/releases/tag/v1.0.0
