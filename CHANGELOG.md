# Changelog

All notable changes to Podkey will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.11] - 2026-09-25

### Fixed

- **sidestr records are read by their push length.** The vendored spec lib moves
  from `373d3eb` to `@sidestr/spec` 0.0.6 (`fa86dac`), whose `recordText`
  compares a push's declared length with its data again (sidestr/spec#17): a
  script that pushed `tal` with `ly:x` after the push read as the record
  `tally:x`. The spend window's asset view and record display now read records
  exactly as validators do. Only `records.mjs` changed in Podkey's vendored set.

## [0.0.10] - 2026-09-25

### Changed

- **Sidechain spends are opt-in.** They are off until you turn them on, in the
  popup's settings or in the spend window the first time a site asks; declining
  answers the site with `code: 'unsupported'`. The settings list the chains in
  use with the signer Podkey settled on for each, and **Forget** drops a chain's
  signer and its saved state; turning spends off forgets every chain. Signer
  pins from 0.0.9 carry over and count as turned on.
- `window.nostr.sidestr.enabled` says whether spends are on, so a page can word
  its own buttons. `signTransaction` is present either way.

### Added

- **Spends open quickly.** Podkey keeps each chain's validated state (coins, the
  last headers and what each coin carries) and the next spend checks only the
  blocks since: on `sidestr:dreamlab`, 545 blocks took 5.9 s to validate the
  first time and 0.3 s after. A saved state whose block hash no longer matches
  the mirror (a reset chain) is dropped and every block is checked again; the
  spend window says which it did.

## [0.0.9] - 2026-09-24

### Added

- **sidestr spends: `window.nostr.sidestr.signTransaction({ chain, tx })`.**
  Podkey is the reference signer for sidestr's browser-signer proposal
  (`proposals/browser-signer.md` in sidestr/spec). A page on any sidestr chain
  asks for a spend and never holds the key. Podkey's own spend window reads the
  chain from its id (the signer's announcement, a mirror it names, every block
  validated), checks that every input is your own mature, unspent coin, computes
  each sighash itself, and shows what leaves your wallet: each recipient (their
  npub, and their profile name when found), what comes back, the fee, and any
  asset (SPEC 12) the spend moves, destroys or burns. Destroying or burning needs
  an explicit tick. Every spend asks, whatever the site is trusted for; the key
  stays in the background and signs only what the window computed, once.
  Refusals reach the page with a `code`: `rejected`, `unsupported`,
  `not-yours`, `invalid` or `unavailable`.
- Chains beside a test network only for now. Each chain's signer is remembered
  on first spend and a different one is refused, since a chain id is a name,
  not a proof.
- The sidestr engine is vendored at pinned commits (`scripts/vendor-sidestr.js`,
  `vendor/sidestr/PINS.json` with a SHA-256 per file): Manifest V3 forbids code
  from the network. Chains that name the EVM rule are `unsupported` until it is
  vendored too.

### Fixed

- Requests from a page wait up to three minutes instead of 30 seconds, so a site
  no longer times out while you unlock Podkey with a security key's PIN and
  touch. Each request's timer is cleared when its answer arrives.

- **Security keys: passkey windows no longer fail straight away.** A passkey
  window started its WebAuthn ceremony on `DOMContentLoaded`, often before the
  new window had focus, and WebAuthn refuses an unfocused document with the same
  `NotAllowedError` as a cancel. Ceremonies now wait for focus.
- **Security keys: the browser goes straight to the key.** The transports a
  credential reports (`usb`, `nfc`, …) are stored and passed in
  `allowCredentials`, so unlock asks to insert and touch the key instead of
  opening the generic chooser that leads with a phone/QR option. Passkeys set up
  before this keep working without the hint.
- **"Unlock with passkey" showed with no passkey set up.** `.btn` overrode the
  `hidden` attribute; a global `[hidden]` rule restores it.
- Ceremony errors name the step and say what to do (PIN, touch, keep the window
  in front); `InvalidStateError`, `NotSupportedError` and `SecurityError` get
  their own messages. Failures show inline with **Try again** instead of an
  `alert()` over a dead window, and set-up says which of its two touches is next.
- Ceremony timeouts are three minutes (time to find a key and set a first PIN);
  EdDSA and RS256 are offered after ES256 for authenticators that lack ES256.
- A window opened only to unlock closes itself once unlocked, handing focus back
  to the site that asked.
- The **Set up** passkey button no longer stays on "Waiting…" after a failure.

### Changed

- The first-approval prompt says that approving also trusts the site from then
  on (it always did; the prompt did not say so).
- Export shows the key as `nsec`, the form other apps and Podkey's import take.
- Plainer copy on the welcome, import and passkey screens; import says it takes
  `nsec` or hex. Stronger text contrast in light and dark, a primary-button fill
  that passes contrast in dark mode, and keyboard focus rings on every control.
  Debug logging removed from the popup.

### Added

- **FIDO2 / WebAuthn passkey master identity (advanced).** Create a Nostr
  identity whose secret key is derived from a hardware passkey via the WebAuthn
  **PRF** extension (HKDF-SHA-256, domain `podkey/nostr-secret/v1`), with no
  passphrase — the passkey reproduces the same key at every unlock. A separate
  *passkey unlock* mode instead wraps an existing passphrase key with an
  AES-256-GCM key derived from the passkey PRF (`podkey/wrap/v1`). Both require a
  PRF-capable authenticator (a phone passkey, a modern security key, or a
  platform authenticator with hmac-secret). The derived flow shows a one-time
  `nsec` backup that must be acknowledged before the identity is persisted.
  Framed as an advanced tier for managing agents or working under compliance
  rules; the ordinary Generate/Import flows are unchanged. Specs:
  `site/passkey-identity.html`, `site/did-nostr.html`.
- **"Start over" on the main screen.** A footer action that wipes the vault,
  public key and passkey config and returns to the setup screen, so an existing
  user can reset to the initial state (and reach passkey-derived creation)
  without locking first.

### Fixed

- **Survive an invalidated extension context.** When the extension is reloaded
  or updated while a page stays open, the orphaned content script no longer
  floods the console with `Extension context invalidated` on every request from
  high-frequency callers; it latches the dead context once, restores native
  `fetch`/XHR, and answers silently until the tab is reloaded.
- **Passkey ceremony compatibility and errors.** Stop requesting a discoverable
  (resident) credential Podkey never uses — it stores the credential id and
  unlocks via `allowCredentials` — fixing `makeCredential` failures on some
  TPM-backed authenticators. Surface actionable messages for a missing PRF /
  hmac-secret extension and for a cancelled or timed-out ceremony, instead of
  the raw WebAuthn `NotAllowedError`.

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
