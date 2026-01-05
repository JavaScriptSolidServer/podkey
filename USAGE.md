# 🚀 How to Use Podkey

## Quick Start Guide

### Step 1: Install Dependencies

```bash
npm install
```

### Step 2: Build the Extension

The extension needs to bundle npm dependencies before it can be loaded:

```bash
npm run build
```

This will:

- Bundle `@noble/secp256k1` and `@noble/hashes` into the service worker
- Create `src/background.bundle.js`
- Update `manifest.json` to use the bundled file

### Step 3: Load Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right corner)
3. Click **"Load unpacked"**
4. Select the `podkey` directory (the one containing `manifest.json`)
5. The extension should now appear in your extensions list!

### Step 4: Pin the Extension

1. Click the puzzle piece icon (🧩) in Chrome's toolbar
2. Find "Podkey" and click the pin icon 📌
3. The Podkey icon (🔑) will now appear in your toolbar

---

## First Time Setup

### Generate a New Key

1. Click the **Podkey icon** (🔑) in your browser toolbar
2. Click **"✨ Generate New Key"**
3. Your new Nostr identity is ready! 🎉

### Import an Existing Key

1. Click the **Podkey icon** (🔑) in your browser toolbar
2. Click **"📥 Import Existing Key"**
3. Paste your 64-character hexadecimal private key
4. Click **"Import"**

⚠️ **Warning**: Never share your private key with anyone!

---

## Using Podkey with Nostr Apps

Podkey provides the standard `window.nostr` API. Any Nostr app that supports NIP-07 will work automatically!

### Example: Get Your Public Key

```javascript
// In any web page or Nostr app
const pubkey = await window.nostr.getPublicKey()
console.log('Your public key:', pubkey)
```

### Example: Sign an Event

```javascript
// Create a Nostr event
const event = {
  kind: 1, // Text note
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: 'Hello from Podkey! 🔑'
}

// Sign it
const signedEvent = await window.nostr.signEvent(event)
console.log('Signed event:', signedEvent)
```

### Example: Full Nostr Client Integration

```javascript
// Check if Podkey is available
if (window.nostr) {
  // Get your public key
  const pubkey = await window.nostr.getPublicKey()

  // Create and sign a note
  const event = {
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: 'Hello Nostr!'
  }

  const signed = await window.nostr.signEvent(event)

  // Now you can publish to relays
  console.log('Ready to publish:', signed)
} else {
  console.log('Podkey not installed')
}
```

---

## Using Podkey with Solid Servers

Podkey automatically handles NIP-98 authentication for Solid servers!

### How It Works

1. When you access a protected resource on a Solid server
2. Podkey detects the 401 authentication requirement
3. You'll be prompted to trust the origin (first time only)
4. Podkey signs an NIP-98 HTTP authentication event
5. The request is retried with the signed header
6. You get access! ✨

**No OAuth redirects. No IdP accounts. Just seamless authentication.**

### Enable Auto-Sign

1. Click the Podkey icon
2. Toggle **"Auto-sign for Solid"** to ON
3. Trusted Solid servers will now authenticate automatically

---

## Managing Trusted Sites

### View Trusted Sites

1. Click the Podkey icon
2. Scroll to **"Trusted Sites"** section
3. See all origins you've granted permissions to

### Remove a Trusted Site

1. Click the Podkey icon
2. Find the site in **"Trusted Sites"**
3. Click **"Remove"** next to the site

---

## Your Identity

### View Your Public Key

1. Click the Podkey icon
2. Your **Public Key** (64-char hex) is displayed
3. Click **"📋 Copy Public Key"** to copy it

### Your DID (Decentralized Identifier)

Your public key is also your `did:nostr` identifier:

```
did:nostr:YOUR_PUBLIC_KEY_HERE
```

This enables:

- ✅ Decentralized identity
- ✅ Cross-platform identity portability
- ✅ Solid pod authentication

### Export Your Private Key

⚠️ **DANGER**: Only do this if you need to backup your key!

1. Click the Podkey icon
2. Click **"Export Key"** in the footer
3. Confirm the warning
4. Your private key will be shown (keep it safe!)

---

## Development Workflow

### After Making Code Changes

1. Make your changes to source files
2. Rebuild the extension:
   ```bash
   npm run build
   ```
3. In Chrome, go to `chrome://extensions/`
4. Click the **reload icon** (🔄) on the Podkey extension
5. Reload any pages using the extension

### Testing

```bash
# Run tests
npm test

# Lint code
npm run lint
```

---

## Troubleshooting

### Extension doesn't show up

- Make sure Developer Mode is enabled
- Check that you selected the correct directory
- Look for errors in `chrome://extensions/` (click "Errors" if shown)

### window.nostr is undefined

- Reload the page after installing Podkey
- Check that the extension is enabled
- Look for conflicts with other Nostr extensions
- Check browser console for errors

### Events not signing

- Make sure you've generated or imported a key
- Check for permission prompts that may be blocked
- Check the extension console (click "service worker" link in chrome://extensions)

### Build errors

- Make sure all dependencies are installed: `npm install`
- Check Node.js version (needs >= 18.0.0)
- Try deleting `node_modules` and `package-lock.json`, then `npm install` again

### Bundle not working

- Make sure esbuild is installed: `npm install`
- Check that `scripts/bundle.js` exists
- Try running: `node scripts/bundle.js` directly

---

## API Reference

### window.nostr.getPublicKey()

Returns your public key (64-char hex).

```javascript
const pubkey = await window.nostr.getPublicKey()
```

### window.nostr.signEvent(event)

Signs a Nostr event. Shows permission prompt if origin is not trusted.

```javascript
const signed = await window.nostr.signEvent({
  kind: 1,
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: 'Hello!'
})
```

### window.nostr.getRelays()

Returns relay configuration (coming soon).

```javascript
const relays = await window.nostr.getRelays()
```

---

## Security Best Practices

1. **Never share your private key** - Anyone with it can control your identity
2. **Review permission prompts** - Only trust sites you know
3. **Use auto-sign carefully** - Only enable for trusted Solid servers
4. **Backup your key** - Export and store it securely if needed
5. **Keep the extension updated** - Check for updates regularly

---

## Need Help?

- **GitHub Issues**: https://github.com/JavaScriptSolidServer/podkey/issues
- **Documentation**: See README.md
- **NIP-07 Spec**: https://github.com/nostr-protocol/nips/blob/master/07.md

---

**Made with 🔑 by the JavaScriptSolidServer team**
