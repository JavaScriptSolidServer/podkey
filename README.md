# 🔑 Podkey

> World-class Nostr wallet extension with Solid superpowers

[![Version](https://img.shields.io/badge/version-0.0.1-blue.svg)](https://github.com/JavaScriptSolidServer/podkey)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![NIP-07](https://img.shields.io/badge/NIP--07-compatible-purple.svg)](https://github.com/nostr-protocol/nips/blob/master/07.md)

Podkey is a beautiful, secure Nostr wallet extension that goes beyond basic key management. Built specifically for the Solid ecosystem, it provides seamless authentication to Solid pods while remaining fully compatible with the broader Nostr ecosystem.

## ✨ What Makes Podkey Different

**Better than nos2x:**
- 🎨 Beautiful, modern UI with soft gradients
- 🔐 Enhanced security and key management
- ⚡ Built-in Solid authentication (NIP-98)
- 📊 Activity logging and trust management
- 🌈 Delightful user experience

**Solid Superpowers:**
- Zero-redirect authentication to Solid servers
- Automatic signing for trusted pods
- did:nostr identity integration
- WebID linking (coming soon)

## 🚀 Features

### Core Functionality
- ✅ **NIP-07 Provider** - Full `window.nostr` API implementation
- ✅ **Key Generation** - Secure cryptographic key generation
- ✅ **Key Import** - Import existing keys (hex format)
- ✅ **Event Signing** - Sign Nostr events with user permission
- ✅ **Solid Auth** - Automatic NIP-98 authentication for Solid servers
- ✅ **Trust Management** - Per-origin permissions
- ✅ **Auto-Sign** - Optional automatic signing for trusted sites
- ✅ **Beautiful UI** - Soft gradients, smooth animations
- ✅ **64-char Hex Keys** - Proper did:nostr format

### Coming Soon
- 🔜 NIP-04 encryption/decryption
- 🔜 Multiple identity support
- 🔜 Relay management
- 🔜 Activity history
- 🔜 nsec/npub Bech32 encoding
- 🔜 WebID linking
- 🔜 Backup & recovery

## 📦 Installation

### For Users

#### Chrome/Edge/Brave

1. Download or clone this repository:
   ```bash
   git clone https://github.com/JavaScriptSolidServer/podkey.git
   cd podkey
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Load the extension:
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `podkey` directory

4. Pin the extension to your toolbar for easy access!

#### Firefox (Coming Soon)

Firefox support is planned for a future release.

### For Developers

```bash
# Clone the repository
git clone https://github.com/JavaScriptSolidServer/podkey.git
cd podkey

# Install dependencies
npm install

# Run tests
npm test

# Lint code
npm run lint
```

## 🎯 Quick Start

### First Time Setup

1. Click the Podkey icon in your browser toolbar
2. Choose one of two options:
   - **Generate New Key** - Creates a fresh Nostr keypair
   - **Import Existing Key** - Import your 64-char hex private key

3. Your identity is now ready! 🎉

### Using with Nostr Apps

Podkey provides the standard `window.nostr` API. Any Nostr app that supports NIP-07 will work automatically:

```javascript
// Get public key
const pubkey = await window.nostr.getPublicKey();

// Sign an event
const event = {
  kind: 1,
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: "Hello from Podkey!"
};

const signedEvent = await window.nostr.signEvent(event);
```

### Using with Solid Servers

When accessing protected resources on a Solid server, Podkey automatically:

1. Detects the 401 authentication requirement
2. Prompts you to trust the origin (first time only)
3. Signs an NIP-98 HTTP authentication event
4. Retries the request with the signed header
5. Grants you access! ✨

**No OAuth redirects. No IdP accounts. Just seamless authentication.**

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
│  │  - Key storage (crypto.js)        │  │
│  │  - Event signing (crypto.js)      │  │
│  │  - Permission management          │  │
│  │  - Solid auto-auth                │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Content Script (src/injected.js) │  │
│  │  - Injects window.nostr           │  │
│  │  - Bridges page ↔ extension       │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│  Web Page (any site)                    │
│  - Accesses window.nostr API            │
│  - Signs events via Podkey              │
│  - Auto-authenticates to Solid          │
└─────────────────────────────────────────┘
```

### Security Model

- 🔒 **Private keys never leave the extension** - Stored in Chrome's local storage
- 🔒 **User permission required** - Every signing operation requires approval
- 🔒 **Per-origin trust** - Granular permissions for each website
- 🔒 **Auto-sign opt-in** - Automatic signing only for explicitly trusted origins
- 🔒 **64-char hex validation** - All keys validated for proper did:nostr format
- 🔒 **Secure event signing** - Uses `@noble/secp256k1` for all cryptography

## 📚 API Reference

### window.nostr

Podkey implements the full [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) specification:

#### `getPublicKey()`

Returns the user's public key (64-char hex).

```javascript
const pubkey = await window.nostr.getPublicKey();
// "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
```

#### `signEvent(event)`

Signs a Nostr event.

```javascript
const event = {
  kind: 1,
  created_at: 1704451200,
  tags: [["t", "nostr"]],
  content: "Hello Nostr!"
};

const signed = await window.nostr.signEvent(event);
// {
//   ...event,
//   id: "...",
//   pubkey: "...",
//   sig: "..."
// }
```

#### `getRelays()` (Coming Soon)

Returns user's relay configuration.

#### `nip04.encrypt()` / `nip04.decrypt()` (Coming Soon)

NIP-04 encryption and decryption.

## 🔐 did:nostr Identity

Podkey ensures all public keys are proper 64-character hexadecimal strings, making them compatible with the [did:nostr](https://github.com/w3c-ccg/did-method-nostr) specification:

```javascript
const pubkey = await window.nostr.getPublicKey();
const did = `did:nostr:${pubkey}`;

console.log(did);
// did:nostr:3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
```

This enables:
- ✅ Decentralized identity
- ✅ WebID linking (future)
- ✅ Cross-platform identity portability
- ✅ Solid pod authentication

## 🎨 UI Screenshots

### Setup Screen
Beautiful onboarding with soft gradients:
- Generate new keys
- Import existing keys
- Clear explanations

### Main Screen
Elegant identity management:
- Public key & DID display
- Copy with one click
- Trust management
- Auto-sign toggle

### Identity Card
Soft yellow-to-blue gradient showcasing:
- Your 64-char hex public key
- Your did:nostr identifier
- Quick copy button

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
├── icons/                 # Extension icons
└── test/                  # Test suite
```

### Tech Stack

- **Cryptography**: [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1)
- **Hashing**: [@noble/hashes](https://github.com/paulmillr/noble-hashes)
- **Storage**: Chrome Storage API
- **UI**: Vanilla JavaScript + CSS Gradients
- **Manifest**: V3 (latest)

### Testing

```bash
# Run all tests
npm test

# Run specific test
node --test test/crypto.test.js
```

### Code Quality

```bash
# Lint code
npm run lint

# Format code
npm run format
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

## 📖 Resources

### Nostr
- [NIP-07: window.nostr](https://github.com/nostr-protocol/nips/blob/master/07.md)
- [NIP-98: HTTP Auth](https://github.com/nostr-protocol/nips/blob/master/98.md)
- [Nostr Protocol](https://github.com/nostr-protocol/nostr)

### Solid
- [Solid Project](https://solidproject.org/)
- [Solid-OIDC Spec](https://solid.github.io/solid-oidc/)
- [did:nostr Method](https://github.com/w3c-ccg/did-method-nostr)

### Related Projects
- [nos2x](https://github.com/fiatjaf/nos2x) - Original NIP-07 extension
- [Alby](https://getalby.com/) - Bitcoin Lightning & Nostr wallet
- [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) - Solid server with NIP-98 support

## 🐛 Troubleshooting

### Extension doesn't show up
- Make sure Developer Mode is enabled in `chrome://extensions/`
- Check that you selected the correct directory
- Look for errors in the Chrome console

### window.nostr is undefined
- Reload the page after installing Podkey
- Check that the extension is enabled
- Look for conflicts with other Nostr extensions

### Events not signing
- Check that you've generated or imported a key
- Look for permission prompts that may be blocked
- Check the extension console for errors

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

## 🙏 Acknowledgments

- Built with 💜 for the Nostr and Solid communities
- Inspired by nos2x and the NIP-07 specification
- Part of the [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer) ecosystem
- Cryptography powered by [@noble](https://github.com/paulmillr/noble-secp256k1)

## 🔗 Links

- **GitHub**: https://github.com/JavaScriptSolidServer/podkey
- **Issues**: https://github.com/JavaScriptSolidServer/podkey/issues
- **NPM**: https://www.npmjs.com/package/podkey (coming soon)
- **Docs**: https://github.com/JavaScriptSolidServer/podkey/wiki (coming soon)

---

**Made with 🔑 by the JavaScriptSolidServer team**

*Podkey v0.0.1 - Your keys, your identity, your data*
