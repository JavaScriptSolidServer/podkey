# 🔑 Podkey

> Browser extension for **did:nostr** and **Solid** authentication

[![Version](https://img.shields.io/badge/version-0.0.6-blue.svg)](https://github.com/JavaScriptSolidServer/podkey/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-green.svg)](LICENSE)
[![NIP-07](https://img.shields.io/badge/NIP--07-compatible-purple.svg)](https://github.com/nostr-protocol/nips/blob/master/07.md)
[![Test Page](https://img.shields.io/badge/test--page-live-brightgreen)](https://javascriptsolidserver.github.io/podkey/test-page/)

**Podkey** is a beautiful, secure browser extension for **did:nostr** and **Solid** authentication. It provides a NIP-07-compatible Nostr wallet that enables seamless authentication to Solid pods using [did:nostr](https://nostrcg.github.io/did-nostr/) identities, while remaining fully compatible with the broader Nostr ecosystem.

## ✨ What Makes Podkey Different

### Better than nos2x

- 🎨 **Beautiful, modern UI** with soft gradients and smooth animations
- 🔐 **Enhanced security** with proper key validation and storage
- ⚡ **Built-in Solid authentication** (NIP-98) for seamless pod access
- 📊 **Trust management** with per-origin permissions
- 🌈 **Delightful user experience** with intuitive design

### did:nostr & Solid Superpowers

- **did:nostr identity** - Full support for [did:nostr](https://nostrcg.github.io/did-nostr/) decentralized identifiers
- **Solid authentication** - Zero-redirect authentication to Solid servers using did:nostr
- **Automatic signing** - Automatic signing for trusted Solid pods
- **WebID linking** - Link did:nostr identities to Solid WebIDs (coming soon)

## 🚀 Quick Start

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/JavaScriptSolidServer/podkey.git
   cd podkey
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Build the extension:**

   ```bash
   npm run build
   ```

4. **Load in Chrome:**

   - Open `chrome://extensions/`
   - Enable "Developer mode" (top-right toggle)
   - Click "Load unpacked"
   - Select the `podkey` directory

5. **Test it:**
   - Visit the [test page](https://javascriptsolidserver.github.io/podkey/test-page/) to verify everything works
   - Click the Podkey icon to generate or import a key

## 🎯 Features

### Core Functionality

- ✅ **NIP-07 Provider** - Full `window.nostr` API implementation
- ✅ **Key Generation** - Secure cryptographic key generation using `@noble/secp256k1`
- ✅ **Key Import** - Import existing 64-char hex private keys
- ✅ **Event Signing** - Sign Nostr events with Schnorr signatures
- ✅ **Trust Management** - Per-origin permissions with auto-approval
- ✅ **Beautiful UI** - Soft gradients, smooth animations
- ✅ **64-char Hex Keys** - Proper did:nostr format compatibility

### Roadmap

- 🔜 NIP-04 encryption/decryption
- 🔜 Multiple identity support
- 🔜 Relay management
- 🔜 Activity history
- 🔜 nsec/npub Bech32 encoding
- 🔜 WebID linking
- 🔜 Backup & recovery
- 🔜 Automatic NIP-98 authentication for Solid servers

## 📚 Usage

### Basic API

```javascript
// Check if Podkey is available
if (window.nostr) {
  // Get your public key
  const pubkey = await window.nostr.getPublicKey()
  console.log('Your public key:', pubkey)

  // Sign an event
  const event = {
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: 'Hello from Podkey! 🔑'
  }

  const signed = await window.nostr.signEvent(event)
  console.log('Signed event:', signed)
}
```

### Testing

Visit the [interactive test page](https://javascriptsolidserver.github.io/podkey/test-page/) to:

- Verify extension installation
- Test key generation and import
- Test event signing with various event types
- View real-time diagnostics and logs

## 🏗️ Architecture

### Components

```
┌─────────────────────────────────────────┐
│  Browser Extension (Podkey)             │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Popup UI (popup/)                │  │
│  │  - Key generation/import          │  │
│  │  - Trust management               │  │
│  │  - Settings & identity display    │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Background Worker (src/)         │  │
│  │  - Key storage (storage.js)       │  │
│  │  - Event signing (crypto.js)      │  │
│  │  - Permission management          │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Content Script (src/injected.js)│  │
│  │  - Injects window.nostr           │  │
│  │  - Bridges page ↔ extension       │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Security Model

- 🔒 **Private keys never leave the extension** - Stored in Chrome's secure local storage
- 🔒 **User permission required** - Every signing operation requires approval (auto-approved for now)
- 🔒 **Per-origin trust** - Granular permissions for each website
- 🔒 **64-char hex validation** - All keys validated for proper did:nostr format
- 🔒 **Secure event signing** - Uses `@noble/secp256k1` v3.0.0 with Schnorr signatures

## 🛠️ Development

### Project Structure

```
podkey/
├── manifest.json          # Extension manifest (MV3)
├── package.json           # npm package configuration
├── src/
│   ├── background.js      # Service worker (message handling)
│   ├── crypto.js          # Key generation & signing
│   ├── storage.js         # Secure key storage
│   ├── injected.js        # Content script (page bridge)
│   └── nostr-provider.js  # window.nostr implementation
├── popup/
│   ├── popup.html         # Popup UI structure
│   ├── popup.css          # Beautiful styling
│   └── popup.js           # Popup logic
├── test-page/
│   └── index.html         # Interactive test page
├── scripts/
│   └── bundle.js          # Build script for dependencies
└── icons/                 # Extension icons
```

### Tech Stack

- **Cryptography**: [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1) v3.0.0
- **Hashing**: [@noble/hashes](https://github.com/paulmillr/noble-hashes) v1.8.0
- **Bundling**: [esbuild](https://esbuild.github.io/)
- **Storage**: Chrome Storage API
- **UI**: Vanilla JavaScript + CSS Gradients
- **Manifest**: V3 (latest)

### Building

```bash
# Install dependencies
npm install

# Build the extension (bundles dependencies)
npm run build

# Lint code
npm run lint

# Run tests
npm test
```

### Testing

1. **Build the extension:**

   ```bash
   npm run build
   ```

2. **Load in Chrome** (see Installation above)

3. **Visit the test page:**

   - Local: Open `test-page/index.html` in your browser
   - Online: https://javascriptsolidserver.github.io/podkey/test-page/

4. **Check the console** for any errors

## 🔐 did:nostr Identity

Podkey is built for **did:nostr** and **Solid** authentication. All public keys are proper 64-character hexadecimal strings, making them fully compatible with the [did:nostr specification](https://nostrcg.github.io/did-nostr/):

```javascript
const pubkey = await window.nostr.getPublicKey()
const did = `did:nostr:${pubkey}`
// did:nostr:3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
```

This enables:

- ✅ **did:nostr** decentralized identifiers per [W3C specification](https://nostrcg.github.io/did-nostr/)
- ✅ **Solid pod authentication** using did:nostr identities
- ✅ Cross-platform identity portability
- ✅ Verifiable credentials and authentication

## 📖 API Reference

### `window.nostr.getPublicKey()`

Returns the user's public key (64-char hex).

```javascript
const pubkey = await window.nostr.getPublicKey()
```

### `window.nostr.signEvent(event)`

Signs a Nostr event. Shows permission prompt if origin is not trusted.

```javascript
const signed = await window.nostr.signEvent({
  kind: 1,
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: 'Hello!'
})
```

### `window.nostr.getRelays()`

Returns relay configuration (coming soon).

```javascript
const relays = await window.nostr.getRelays()
```

## 🤝 Contributing

We love contributions! Here's how to get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Ensure tests pass (`npm test`)
6. Commit (`git commit -m 'Add amazing feature'`)
7. Push (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Contribution Ideas

- 🎨 Icon design (16px, 48px, 128px)
- 📝 Documentation improvements
- 🧪 Additional test coverage
- 🌐 i18n/localization
- ✨ NIP-04 encryption
- 🔧 Bug fixes
- 🚀 Performance improvements

## 🐛 Troubleshooting

### Extension doesn't show up

- Make sure Developer Mode is enabled in `chrome://extensions/`
- Check that you selected the correct directory
- Look for errors in the Chrome console

### window.nostr is undefined

- Reload the page after installing Podkey
- Check that the extension is enabled
- Look for conflicts with other Nostr extensions
- Check the browser console for errors

### Events not signing

- Make sure you've generated or imported a key
- Check the extension console (click "service worker" in chrome://extensions)
- Look for permission prompts that may be blocked

### Build errors

- Make sure all dependencies are installed: `npm install`
- Check Node.js version (needs >= 18.0.0)
- Try deleting `node_modules` and `package-lock.json`, then `npm install` again

## 📄 License

AGPL-3.0 License - see [LICENSE](LICENSE) for details

## 🙏 Acknowledgments

- Built with 💜 for the Nostr and Solid communities
- Inspired by [nos2x](https://github.com/fiatjaf/nos2x) and the NIP-07 specification
- Part of the [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer) ecosystem
- Cryptography powered by [@noble](https://github.com/paulmillr/noble-secp256k1)

## 🔗 Links

- **GitHub**: https://github.com/JavaScriptSolidServer/podkey
- **Issues**: https://github.com/JavaScriptSolidServer/podkey/issues
- **Test Page**: https://javascriptsolidserver.github.io/podkey/test-page/
- **did:nostr Specification**: https://nostrcg.github.io/did-nostr/
- **NIP-07 Spec**: https://github.com/nostr-protocol/nips/blob/master/07.md
- **NIP-98 Spec**: https://github.com/nostr-protocol/nips/blob/master/98.md
- **Solid Project**: https://solidproject.org/

---

**Made with 🔑 by the JavaScriptSolidServer team**

_Podkey v0.0.6 - Your keys, your identity, your data_
