# Chrome Web Store submission pack — Podkey

Everything needed to file Podkey on the Chrome Web Store. Copy the fields
straight into the Developer Dashboard. Last prepared: 2026-06-16, against
version 0.0.8.

## 0. Before you start (one-time)

- Pay the **$5** developer registration fee at <https://chrome.google.com/webstore/devconsole>.
- Enable **2-Step Verification** on the publishing Google account (required to publish).
- Set **publisher identity** (name/contact) and answer the **trader / non-trader**
  question (EU DSA). A free, open-source tool with no commercial intent is
  **non-trader**.

## 1. Package

The uploadable ZIP is produced by the build, with test files excluded:

```bash
npm run build                       # bundles the background worker and popup
zip -r podkey-extension.zip manifest.json src popup icons -x '*.test.js'
```

CI also uploads this artifact (`podkey-extension`) on every run of `ci.yml`.
Bump `manifest.json` `version` to **0.0.8** before zipping (README/CHANGELOG
already say 0.0.8).

## 2. Store listing

- **Item name:** `Podkey`
- **Summary** (132 char max):
  > `One key for Nostr, did:nostr and Solid: a NIP-07 signer and Solid (NIP-98) login. Your key is encrypted and stays on your device.`
- **Category:** `Developer Tools`
- **Language:** `English (UK)`
- **Detailed description:**

```
Podkey holds one cryptographic key on your device and uses it three ways:

• Nostr signing (NIP-07). Podkey puts a standard window.nostr provider on the
  page — getPublicKey, signEvent, and nip44.encrypt/decrypt — so any NIP-07
  Nostr client works with it, unchanged.

• did:nostr identity. Your public key is your did:nostr identifier, portable
  across any NIP-07-aware app.

• Solid login (NIP-98). Podkey authenticates to Solid pods over NIP-98 HTTP
  auth, keyed to your did:nostr. No OAuth redirect and no identity-provider
  account.

Your key, encrypted at rest:
Podkey stores the private key only as an AES-256-GCM ciphertext, wrapped by a
passphrase using scrypt. The raw key never touches disk. When you unlock, the
key is held in memory for the browser session so signing is fast, then cleared
when the browser closes.

Per-site consent:
An untrusted site raises a consent prompt on its first request; closing it, or
a 60-second timeout, denies it. Approving grants per-origin trust you can revoke
at any time from the popup.

Private by design:
No servers, no accounts, no analytics. Podkey makes no network requests of its
own and collects nothing. Open source under AGPL-3.0.

Signing, NIP-44 and NIP-98 all run in the background service worker; web pages
only ever see a public key, a signature, a NIP-44 payload, or an auth header.
```

- **Privacy policy URL:** `https://jss.live/podkey/privacy.html`
- **Homepage/support:** `https://github.com/JavaScriptSolidServer/podkey`
- **Screenshots:** see `store/screenshots/` (1280×800). At least one is required.

## 3. Single purpose

> Podkey is a key signer. It holds one cryptographic key on the user's device
> and uses it to sign Nostr events (NIP-07) and to authenticate to Solid pods
> (NIP-98). Every permission serves that one purpose.

## 4. Permission justifications (per-permission fields)

- **`storage`**
  > Stores the user's public key and their passphrase-encrypted private key
  > locally, plus the list of sites the user has trusted and their auto-sign
  > preference. No data leaves the device.

- **Host permission `<all_urls>`** (the field reviewers scrutinise most)
  > Podkey is a NIP-07 signer, so it must expose a window.nostr provider on any
  > page where the user runs a Nostr or Solid app, and — only for origins the
  > user has explicitly trusted — attach a NIP-98 Authorization header to that
  > user's own requests. A fixed host list is not possible because users choose
  > which Nostr/Solid sites they visit. Podkey does not read, collect, store, or
  > transmit page content or browsing history; host access is used solely to
  > inject the signer and to authenticate requests the user initiates to sites
  > they approved. Signing is gated by per-origin consent and is revocable.

- **Remote code:** `No`. All JavaScript is bundled into the extension
  (esbuild → `src/background.bundle.js`); nothing is fetched and executed at
  runtime. CSP is `script-src 'self'`.

## 5. Data use disclosures (Privacy practices tab)

Podkey does **not** collect or transmit user data off the device. Declarations:

- Data handled: a Nostr keypair is created/held **locally** (the private key
  encrypted at rest). This is **not** transmitted to the developer or any third
  party, so it is not "collected" in Google's sense. Do not tick any "we collect
  / transmit" data categories that imply off-device transfer.
- Certify the required statements:
  - ✅ Not sold or transferred to third parties (outside approved use cases).
  - ✅ Used/transferred only for the single purpose above.
  - ✅ Not used or transferred to determine creditworthiness or for lending.
- Limited Use: Podkey uses local data only to provide its signing/auth feature.

If the form forces a category, the closest honest selection is
"Authentication information", with the note that it is stored locally only and
never transmitted — and link the privacy policy, which states exactly this.

## 6. Distribution — recommendation

**Unlisted.** Installable by direct link with auto-updates and Web Store trust,
but not surfaced in search/category browsing. Lowest review/abuse profile for a
broad-permission key tool, and fits a niche signer for the did:nostr / Solid
ecosystem. Switch to **Public** later for reach, or **Private** (trusted testers
/ a Workspace group) to restrict to your own circle.

Self-hosting (load-unpacked from the repo) stays available for power users, but
gives no auto-updates and shows developer-mode warnings.

## 7. Likely review friction & how this pack pre-empts it

- **Broad `<all_urls>`** → answered by the justification above (inherent to a
  NIP-07 provider; no page data read/exfiltrated; per-origin consent).
- **Handles keys/credentials** → the privacy policy + Limited Use certification
  explain local-only, encrypted-at-rest handling.
- **Single purpose** → one clear function (a signer); no bundled unrelated
  features.
- Typical review time: a few business days; longer is normal for broad
  permissions + key handling.
