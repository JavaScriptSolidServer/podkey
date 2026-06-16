# Podkey Privacy Policy

_Last updated: 2026-06-16_

Podkey is a browser extension that holds a Nostr/[did:nostr](https://nostrcg.github.io/did-nostr/)
key on your device and uses it to sign Nostr events ([NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md))
and to authenticate to [Solid](https://solidproject.org) pods over
[NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md). It is a
**local signer**: your key never leaves your device, and Podkey has no servers,
no accounts, and no analytics.

## What Podkey stores, and where

All data is stored **locally** in the browser's extension storage. Nothing is
sent to the Podkey developers or to any third party.

| Data | Where | Notes |
|------|-------|-------|
| **Private key** | `chrome.storage.local`, **encrypted** | Stored only as an AES-256-GCM ciphertext, wrapped by a key derived from your passphrase with scrypt. The plaintext key is never written to disk. |
| **Private key (unlocked)** | `chrome.storage.session`, in-memory | After you unlock with your passphrase, the decrypted key is held in memory for the browser session so signing is fast. It is cleared when the browser closes. |
| **Public key** | `chrome.storage.local` | Your `did:nostr` identity. Not secret. |
| **Trusted origins** | `chrome.storage.local` | The sites you have approved to sign without re-prompting, and an optional per-site auto-sign preference. You can revoke any of them from the popup. |

There is **no telemetry, no tracking, no advertising identifiers, and no
remote logging.** Podkey collects none of your browsing history or page content.

## How your key is used

- **Signing** (NIP-07 `signEvent`, `nip44.encrypt/decrypt`) and **Solid
  authentication** (NIP-98) happen entirely inside the extension's background
  service worker. The raw private key is never exposed to web pages: only the
  resulting signature, ciphertext/plaintext, or `Authorization` header crosses
  to the page.
- A site you have not approved triggers a consent prompt on its first request.
  Closing the prompt, or a 60-second timeout, denies it.
- Podkey makes **no network requests of its own.** A NIP-98 `Authorization`
  header is attached only to requests **you** initiate to a Solid/Nostr server
  you have trusted; the data goes to that server, under your control, not to
  Podkey.

## Permissions, and why they are needed

- **`storage`**: to keep the encrypted key, your public key, and your trusted
  sites locally, as described above.
- **Host access (`<all_urls>`)**: Podkey is a NIP-07 signer, so it injects a
  `window.nostr` provider into pages and, for sites you have trusted, attaches
  NIP-98 auth to your own requests. This requires script access to the pages
  where you use a Nostr/Solid app. Podkey **does not read, collect, or transmit
  page content or browsing history**; host access is used solely to expose the
  signer and to intercept auth for origins you have explicitly approved.

## Data sharing and retention

- Podkey **does not sell or share** any data. There is no data broker, no
  third-party processor, and no off-device transfer of your key or activity.
- All data remains on your device until you delete it. **Removing the
  extension, or using "Forget key" in the popup, erases the stored vault, public
  key, and trusted sites.** Back up your private key before doing so. Without a
  backup it cannot be recovered.

## Your control

- Unlock / lock your key on demand from the popup.
- Review and revoke trusted sites at any time.
- Export your private key (after unlocking) to back it up.
- Forget the key entirely to start over.

## Contact

Podkey is open source under AGPL-3.0. Questions, issues, or security reports:
<https://github.com/JavaScriptSolidServer/podkey/issues>.

This policy may be updated as the extension evolves; the "Last updated" date
above reflects the current version. Material changes will be noted in the
project [CHANGELOG](CHANGELOG.md).
