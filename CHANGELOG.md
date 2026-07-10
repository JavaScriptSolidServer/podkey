# Changelog

All notable changes to Podkey will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.8] - 2026-07-10

### Added

- **NIP-44 (v2) encryption.** `window.nostr.nip44.encrypt(pubkey, plaintext)`
  and `nip44.decrypt(pubkey, ciphertext)` for NIP-17 / NIP-59 gift-wrapped
  direct messages. The crypto runs in the background worker (`@noble/ciphers`
  chacha20, `@noble/hashes` hkdf/hmac, ECDH via `@noble/secp256k1`) and is
  checked against the official NIP-44 test vectors. The private key stays in
  the worker.
- **Per-origin signing consent.** The first request from a site opens an
  approval popup; closing it or a 60-second timeout denies. Approving grants
  per-origin trust that you can revoke from the popup.
- **Encrypted-at-rest key vault.** The private key is persisted only as an
  AES-256-GCM ciphertext in `chrome.storage.local`, wrapped by a scrypt-derived
  key from the user's passphrase (`src/vault.js`). On unlock the decrypted key
  is cached in `chrome.storage.session` for fast signing and cleared when the
  browser closes; the raw key never touches disk. New `UNLOCK_VAULT`/`LOCK_VAULT`
  messages, a popup unlock screen, and a clear "Podkey is locked" prompt replace
  the previous "No keypair found" error after a restart.
- **NIP-98 Solid authentication.** Opt-in HTTP auth to Solid pods. Each token
  carries a fresh 16-byte nonce and binds the request body hash and the final
  redirect-aware URL, so one token authorises one request. Trusted Solid hosts
  are matched exactly.
- **Schnorr self-verify.** Every signature is checked against the public key
  before it is returned.
- **Extension icons** at 16, 48 and 128px, and a `script-src 'self'`
  content-security policy across the popup and test page.
- **Continuous integration.** `.github/workflows/ci.yml` runs build, test and
  lint on every pull request and push to `main`, and uploads a sideloadable
  extension zip. The 141-case suite covers signing, NIP-44 vectors, NIP-98
  token shape, the content-script message whitelist, the consent flow, and the
  vault crypto (round-trip, wrong passphrase, tamper, salt/iv freshness).

### Changed

- A trusted origin signs any event kind without a prompt, so Podkey works as a
  general NIP-07 signer. A normal client publishes kind 0, 10002 and 22242 on
  every load; those no longer raise a prompt once you trust the site. Untrusted
  origins still prompt, and approving one grants trust.
- The `window.nostr` provider exposes `getPublicKey`, `signEvent` and
  `nip44.{encrypt,decrypt}`.
- The popup fits within the browser popup height, keeping the Export and GitHub
  links in view.

## [0.0.7] - 2024-12-XX

### Changed

- Improved installation guide on test page with comprehensive step-by-step instructions
- Prioritized direct extension installation over git clone workflow
- Added developer section for building from source

## [0.0.6] - 2024-12-XX

### Changed

- Code formatting improvements (prettier)
- Test page installation guide formatting

## [0.0.5] - 2024-12-XX

### Added

- Comprehensive installation instructions on test page
- Clear guidance for users on how to install and use the extension
- Links to did:nostr specification throughout documentation

### Changed

- License changed from MIT to AGPL-3.0
- All descriptions updated to emphasize did:nostr and Solid authentication
- Test page now shows installation guide when extension is not detected
- Popup UI updated to mention did:nostr and Solid

### Documentation

- Added did:nostr specification link (https://nostrcg.github.io/did-nostr/)
- Updated README to clearly position Podkey as extension for did:nostr and Solid
- Enhanced test page with better user guidance

## [0.0.4] - 2024-12-XX

### Fixed

- Fixed key generation bug: Changed `randomPrivateKey()` to `randomSecretKey()` for @noble/secp256k1 v3.0.0 compatibility
- Added comprehensive error logging for debugging
- Fixed storage test suite (removed beforeEach, using clearStorage function)

### Added

- Comprehensive test suite with 20 passing tests
  - Crypto function tests (key generation, signing, verification)
  - Storage function tests (keypair management, trusted origins, auto-sign)
- Better error handling and logging in background service worker

## [0.0.3] - 2024-12-XX

### Added

- Interactive test page with real-time diagnostics
- GitHub Pages deployment for test page
- Comprehensive README with usage examples
- Proper hash function configuration for @noble/secp256k1 v3.0.0
- Type safety improvements for all API responses
- Better error handling and logging
- Auto-approval for permission requests (service worker compatible)

### Fixed

- Syntax error in `nostr-provider.js` (async nip04 assignment)
- Event hash calculation now includes pubkey correctly (NIP-01 compliant)
- Signature calculation now converts hex to bytes before signing
- Hash functions properly configured for @noble/secp256k1 v3.0.0
- Response type safety (ensures strings/arrays are correct types)
- Bundle script now properly bundles npm dependencies

### Changed

- Upgraded @noble/secp256k1 from v2.3.0 to v3.0.0
- Updated to use proper Schnorr signature API
- Improved error messages and diagnostics
- Better handling of undefined/null responses

### Technical

- Created bundle script using esbuild
- Proper ES module support in service worker
- All dependencies bundled for Chrome extension compatibility

## [0.0.2] - Initial Development

### Added

- Basic NIP-07 provider implementation
- Key generation and import
- Event signing with Schnorr signatures
- Popup UI with beautiful gradients
- Trust management system
- Storage abstraction layer

[0.0.7]: https://github.com/JavaScriptSolidServer/podkey/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/JavaScriptSolidServer/podkey/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/JavaScriptSolidServer/podkey/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/JavaScriptSolidServer/podkey/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/JavaScriptSolidServer/podkey/compare/v0.0.2...v0.0.3
