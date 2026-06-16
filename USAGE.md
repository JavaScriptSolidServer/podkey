# 🚀 How to Use Podkey

**Podkey** is a browser extension for **did:nostr** and **Solid** authentication. It puts a NIP-07 `window.nostr` provider on every page and authenticates to Solid pods over NIP-98, both keyed to your [did:nostr](https://nostrcg.github.io/did-nostr/) identity.

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
3. Choose an **encryption passphrase** (at least 8 characters) and confirm it
4. Your new Nostr identity is ready, sealed under your passphrase! 🎉

### Import an Existing Key

1. Click the **Podkey icon** (🔑) in your browser toolbar
2. Click **"📥 Import Existing Key"**
3. Paste your 64-character hexadecimal private key
4. Choose an **encryption passphrase** (at least 8 characters) and confirm it
5. Click **"Import"**

⚠️ **Warning**: Never share your private key with anyone!

### Unlocking after a browser restart

Your key is encrypted at rest, so when you restart the browser the popup shows
an **Unlock** screen. Enter your passphrase to unlock it for the session — until
you do, signing requests show a clear "Podkey is locked" prompt rather than
failing silently. Your passphrase is never stored and cannot be recovered, so
keep a backup of your private key (and the passphrase).

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

Podkey authenticates to Solid servers over NIP-98, using your did:nostr key.

### How it works

1. You request a protected resource on a Solid server.
2. The server replies with a 401.
3. Podkey asks you to trust the origin (first time only).
4. Podkey signs a NIP-98 HTTP authentication event.
5. The request is retried with the signed header, and you get access.

No OAuth redirect, no identity-provider account.

### Enable auto-sign

Auto-sign is off by default. To turn it on:

1. Click the Podkey icon.
2. Toggle **Auto-sign for Solid** to on.
3. Trusted Solid servers then authenticate without a prompt.

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

1. Click the Podkey icon (unlock it first if it shows the Unlock screen)
2. Click **"Export Key"** in the footer
3. Confirm the warning
4. Your private key will be shown (keep it safe!)

You can also **Lock** the key on demand from the footer, or **Forget key** from
the Unlock screen to wipe the encrypted vault and start over.

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

Signs a Nostr event. A trusted origin signs with no prompt; a new origin
prompts once, and approving it grants trust.

```javascript
const signed = await window.nostr.signEvent({
  kind: 1,
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: 'Hello!'
})
```

### window.nostr.nip44.encrypt(pubkey, plaintext) / .decrypt(pubkey, ciphertext)

NIP-44 (v2) encryption for NIP-17 / NIP-59 direct messages. The private key
stays in the background worker.

```javascript
const payload = await window.nostr.nip44.encrypt(peerPubkey, 'hello')
const plaintext = await window.nostr.nip44.decrypt(peerPubkey, payload)
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
