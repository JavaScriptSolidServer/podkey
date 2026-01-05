# Changelog

All notable changes to Podkey will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-XX

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

[0.1.0]: https://github.com/JavaScriptSolidServer/podkey/compare/v0.0.2...v0.1.0
