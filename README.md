# 🔑 Podkey

> Browser extension for **did:nostr** and **Solid** authentication

[![Version](https://img.shields.io/badge/version-0.0.8-blue.svg)](https://github.com/JavaScriptSolidServer/podkey/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-green.svg)](LICENSE)
[![NIP-07](https://img.shields.io/badge/NIP--07-compatible-purple.svg)](https://github.com/nostr-protocol/nips/blob/master/07.md)
[![Test Page](https://img.shields.io/badge/test--page-live-brightgreen)](https://javascriptsolidserver.github.io/podkey/test-page/)

Podkey is a NIP-07 signer for Nostr and an HTTP-auth signer for Solid pods. It
puts a `window.nostr` provider on every page, signs events with your key, and
authenticates to Solid servers over NIP-98 using your
[did:nostr](https://nostrcg.github.io/did-nostr/) identity. The private key
stays inside the extension and never reaches the page.

## What it does

- **NIP-07 provider**: `getPublicKey`, `signEvent`, and `nip44.{encrypt,decrypt}`
  on `window.nostr`, so any NIP-07 Nostr client works without extra wiring.
- **Solid authentication**: NIP-98 HTTP auth to Solid pods, keyed to your
  did:nostr identifier. No OAuth redirect, no identity-provider account.
- **NIP-44 (v2) encryption** for NIP-17 / NIP-59 gift-wrapped direct messages.
  The key never leaves the background worker; only the ciphertext or plaintext
  crosses to the page.
- **Per-origin trust**: approve a site once and it signs without asking again.
  Revoke any site from the popup.
- **did:nostr identity**: every public key is a 64-character hex string, usable
  directly as `did:nostr:<pubkey>`.

## Security model

- **Encrypted at rest.** The private key is persisted only as an AES-256-GCM
  ciphertext in `chrome.storage.local`, wrapped by a key derived from your
  passphrase with scrypt. The raw key is never written to disk.
- **Unlocked in memory.** When you unlock with your passphrase, the decrypted
  key is cached in `chrome.storage.session` for the browser session so signing
  is fast; it is cleared when the browser closes, so you re-unlock next time. It
  is never copied to the page; signing, NIP-44 and NIP-98 all run in the
  background service worker.
- A site you have not approved raises a consent popup on its first request.
  Closing the popup, or a 60-second timeout, denies it. Approving grants
  per-origin trust that you can revoke at any time from the popup.
- Signatures use `@noble/secp256k1` v3 Schnorr and are verified against the
  public key before they are returned.
- Each NIP-98 token carries a fresh 16-byte nonce and binds the request body
  hash and the final (redirect-aware) URL, so one token authorises one request.
- NIP-98 auto-authentication for Solid is opt-in and off by default. When it is
  on, it matches trusted Solid hosts exactly, so a lookalike such as
  `inrupt.net.evil.com` is rejected.
- The popup and test page run under a `script-src 'self'` content-security
  policy with no inline scripts.

## Install

### From a packaged release

1. Download the latest `podkey-extension` build from the
   [releases page](https://github.com/JavaScriptSolidServer/podkey/releases) and
   unzip it.
2. Open `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** (top-right).
4. Click **Load unpacked** and select the unzipped folder containing
   `manifest.json`.

### From source

```bash
git clone https://github.com/JavaScriptSolidServer/podkey.git
cd podkey
npm install
npm run build      # bundles the background worker and passkey-enabled popup
```

Then load the `podkey` directory as an unpacked extension (steps 2–4 above).

Pin the toolbar icon (🔑), open it, and generate or import a 64-character hex
key, choosing an **encryption passphrase**. The key is sealed under that
passphrase (see [Security model](#security-model)); you unlock it once per
browser session. The [test page](https://javascriptsolidserver.github.io/podkey/test-page/)
detects the extension and runs live signing checks.

## Usage

```javascript
if (window.nostr) {
  const pubkey = await window.nostr.getPublicKey()

  const signed = await window.nostr.signEvent({
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: 'Hello from Podkey! 🔑'
  })
}
```

### API

#### `window.nostr.getPublicKey()`

Returns your public key as 64-character hex. Prompts once for a new origin.

#### `window.nostr.signEvent(event)`

Signs a Nostr event and returns it with `id`, `pubkey` and `sig` populated. A
trusted origin signs with no prompt; a new origin prompts once, and approving it
grants trust.

#### `window.nostr.nip44.encrypt(pubkey, plaintext)` / `window.nostr.nip44.decrypt(pubkey, ciphertext)`

NIP-44 (v2) encryption for NIP-17 / NIP-59 direct messages. The private key
stays in the background worker; only the base64 payload or decrypted plaintext
crosses to the page.

```javascript
const peer = '<64-char hex pubkey>'
const payload = await window.nostr.nip44.encrypt(peer, 'hello')
const plaintext = await window.nostr.nip44.decrypt(peer, payload)
```

## Architecture

```
┌─────────────────────────────────────────┐
│  Podkey (MV3 extension)                  │
│                                          │
│  Popup UI (popup/)                       │
│   key generation / import, trusted-site  │
│   management, identity display, consent  │
│                                          │
│  Background worker (src/)                │
│   encrypted key vault (vault.js) + session│
│   cache (storage.js), signing & NIP-44   │
│   (crypto.js, nip44.js), NIP-98 auth,    │
│   per-origin permission gate             │
│                                          │
│  Page bridge (src/injected.js)           │
│   injects window.nostr, relays requests  │
│   to the worker, whitelists message types│
└─────────────────────────────────────────┘
```

The private key is read only inside the background worker. The page sees a
public key, a signed event, a NIP-44 payload, or a NIP-98 header, never the key
itself.

## did:nostr identity

A Podkey public key is a 64-character hex string, so it is also a
[did:nostr](https://nostrcg.github.io/did-nostr/) identifier:

```javascript
const pubkey = await window.nostr.getPublicKey()
const did = `did:nostr:${pubkey}`
// did:nostr:3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
```

That identifier authenticates you to Solid pods and travels across any
NIP-07-aware app.

## Where Podkey fits

Podkey sits at the join of two mature, independently-built ecosystems and
consolidates them behind one key:

- **Nostr signing already exists.** NIP-07 browser signers (nos2x, Alby, and
  others) are well-established. Podkey is fully NIP-07 compatible, so every
  existing Nostr client works with it unchanged. It builds on that surface
  rather than replacing it.
- **[did:nostr](https://github.com/topics/did-nostr)** is an emerging ecosystem
  of decentralised-identity tooling built on Nostr keys. Podkey treats your
  public key as a first-class `did:nostr` identifier in its own right.
- **[Solid](https://solidproject.org)** (the W3C-aligned personal-data-pod
  standard) is highly mature but has historically required OIDC/WebID identity
  providers. Podkey authenticates to Solid pods over NIP-98 keyed to your
  did:nostr, with no OAuth redirect and no IdP account.

The novel part is the **consolidation**: one locally-held, encrypted key that
is simultaneously your Nostr signer, your `did:nostr` identity, and your Solid
login. Podkey extends what existing Nostr signers do (NIP-07) with did:nostr
identity and Solid/NIP-98 authentication, and adds an encrypted-at-rest vault on
top.

## Development

```bash
npm install
npm run build      # bundle dependencies into the service worker
npm test           # node --test, 141 cases (incl. vault crypto)
npm run lint       # eslint, no-unused-vars as error
```

```
podkey/
├── manifest.json          # MV3 manifest (CSP script-src 'self')
├── src/
│   ├── background.js      # service worker: message handling, consent gate
│   ├── crypto.js          # key generation & Schnorr signing
│   ├── nip44.js           # NIP-44 v2 encrypt/decrypt
│   ├── nip98-interceptor.js # page-context NIP-98 fetch/XHR auth
│   ├── vault.js           # AES-GCM encrypted-at-rest key vault (scrypt)
│   ├── storage.js         # session key cache + trusted-origin storage
│   ├── injected.js        # content-script page bridge
│   └── nostr-provider.js  # window.nostr implementation
├── popup/                 # popup + approval UI
├── test-page/             # install + live-signing test page
└── scripts/bundle.js      # esbuild bundler
```

Tests cover the consent flow, NIP-44 against the official spec vectors, NIP-98
token shape, the content-script message whitelist, and signature self-verify.
CI runs build, test and lint on every pull request and push to `main`, and
uploads a sideloadable extension zip.

## Roadmap

- NIP-04 encryption / decryption
- Multiple identities
- Relay management and `getRelays`
- `nsec` / `npub` Bech32 display
- WebID linking for did:nostr ↔ Solid
- Key backup and recovery

## Contributing

1. Fork and branch (`git checkout -b feature/your-change`).
2. Make the change and add or update tests.
3. Run `npm test` and `npm run lint` until both pass.
4. Open a pull request.

Good first contributions: test coverage, NIP-04, i18n, `nsec`/`npub` Bech32
display, and documentation.

## Troubleshooting

**`window.nostr` is undefined.** Reload the page after installing, confirm the
extension is enabled, and check for another Nostr extension claiming
`window.nostr`.

**Events will not sign.** Generate or import a key first. If the popup shows
**Unlock**, the vault is locked (e.g. after a browser restart). Enter your
passphrase to unlock for the session. Also check the service worker console
(the "service worker" link on `chrome://extensions`) for a blocked consent
prompt.

**Build errors.** Reinstall dependencies (`npm install`) and confirm Node.js
18 or newer.

## License

AGPL-3.0. See [LICENSE](LICENSE).

## Links

- **Repository**: https://github.com/JavaScriptSolidServer/podkey
- **Issues**: https://github.com/JavaScriptSolidServer/podkey/issues
- **Privacy policy**: [PRIVACY.md](PRIVACY.md)
- **Test page**: https://javascriptsolidserver.github.io/podkey/test-page/
- **did:nostr**: https://nostrcg.github.io/did-nostr/ · [ecosystem](https://github.com/topics/did-nostr)
- **NIP-07**: https://github.com/nostr-protocol/nips/blob/master/07.md
- **NIP-98**: https://github.com/nostr-protocol/nips/blob/master/98.md
- **Solid**: https://solidproject.org/

---

_Podkey — your keys, your identity, your data._
