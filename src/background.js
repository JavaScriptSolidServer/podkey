/**
 * Podkey - Background Service Worker
 * Coordinates key management, signing, and Solid auto-auth
 */

import { generateKeypair, signEvent, getPublicKey } from './crypto.js';
import {
  getConversationKey,
  encrypt as nip44Encrypt,
  decrypt as nip44Decrypt,
  bytesToHex as nip44BytesToHex
} from './nip44.js';
import {
  storeKeypair,
  getKeypair,
  hasKeypair,
  getStoredPublicKey,
  clearSessionKey,
  isTrustedOrigin,
  addTrustedOrigin,
  getAutoSign
} from './storage.js';
import { createVault, unlockVault, hasVault } from './vault.js';
import { normalizeSecretKeyToHex } from './keyformat.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

// Set DEBUG=true to emit verbose diagnostics. Off by default so the extension
// never logs public keys, DIDs, NIP-98 events, or Authorization headers.
const DEBUG = false;

if (DEBUG) console.log('[Podkey] Background service worker started');

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
  console.log('[Podkey] Extension installed');

  const keyExists = await hasKeypair();
  if (!keyExists) {
    console.log('[Podkey] No keypair found - user will need to generate or import one');
  } else {
    console.log('[Podkey] Keypair already exists');
  }
});

// Pending signing approval promises: requestId -> resolve function
const pendingApprovals = new Map();

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Handle signing approval responses from the approve popup
  if (message.type === 'APPROVE_SIGNING') {
    const resolve = pendingApprovals.get(message.requestId);
    if (resolve) {
      pendingApprovals.delete(message.requestId);
      resolve(message.approved === true);
    }
    return; // synchronous, no sendResponse needed
  }

  handleMessage(message, sender)
    .then(result => {
      // Never log `result`: it may be a public key, signed event, or
      // Authorization header (token). Log only the message type under DEBUG.
      if (DEBUG) console.log('[Podkey] Message handled:', message.type);
      sendResponse(result);
    })
    .catch(error => {
      console.error('[Podkey] Error handling message:', message.type, error);
      sendResponse({ error: error.message });
    });

  return true; // Async response
});

/**
 * Handle incoming messages
 */
async function handleMessage (message, sender) {
  const { type, origin } = message;

  if (DEBUG) console.log('[Podkey] Message received:', type, 'from', origin || 'popup');

  switch (type) {
    case 'GET_PUBLIC_KEY':
      return await handleGetPublicKey(origin, sender);

    case 'SIGN_EVENT':
      return await handleSignEvent(message.event, origin, sender);

    case 'GENERATE_KEYPAIR':
      return await handleGenerateKeypair(message.passphrase);

    case 'IMPORT_KEYPAIR':
      return await handleImportKeypair(message.privateKey, message.passphrase);

    case 'UNLOCK_VAULT':
      return await handleUnlockVault(message.passphrase);

    case 'LOCK_VAULT':
      return await handleLockVault();

    case 'GET_KEYPAIR_STATUS':
      return await handleGetKeypairStatus();

    case 'NIP44_ENCRYPT':
      return await handleNip44Encrypt(message.pubkey, message.plaintext, origin);

    case 'NIP44_DECRYPT':
      return await handleNip44Decrypt(message.pubkey, message.ciphertext, origin);

    case 'NIP44_GET_CONVERSATION_KEY':
      return await handleNip44GetConversationKey(message.pubkey, origin);

    case 'CREATE_NIP98_AUTH_HEADER':
      return await createNip98AuthHeader(
        message.url,
        message.method,
        message.body,
        message.bodyHash
      );

    default:
      throw new Error(`Unknown message type: ${type}`);
  }
}

/**
 * Coalesce concurrent unlock requests behind a SINGLE passphrase prompt.
 *
 * A page that logs in fires several key-using requests back to back —
 * `GET_PUBLIC_KEY` (identity), `SIGN_EVENT` (the NIP-42 relay AUTH), and
 * `nip44.decrypt` (gift-wrapped DMs). Each one used to hit `ensureUnlocked`
 * while the vault was still locked, open its OWN popup, and reject immediately.
 * The user therefore faced three passphrase prompts, and the rejected
 * `nip44.decrypt` made encrypted DMs silently un-readable (the relying app saw a
 * "locked" error, not a decryptable message). Here the first locked caller opens
 * ONE popup and every concurrent caller awaits the same unlock; a single
 * passphrase entry — which writes the key into `chrome.storage.session` — resolves
 * them all. `chrome.storage.onChanged` reliably wakes the MV3 service worker, so
 * the wait survives an idle eviction of the background. Returns `true` if the
 * vault became unlocked, `false` on timeout.
 */
let pendingUnlock = null;

function awaitUnlock () {
  if (pendingUnlock) return pendingUnlock;

  pendingUnlock = new Promise((resolve) => {
    let settled = false;
    let timer;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      chrome.storage.onChanged.removeListener(onChange);
      clearTimeout(timer);
      pendingUnlock = null;
      resolve(ok);
    };
    // Any write to session storage may be the unlocked key landing — confirm
    // with hasKeypair() rather than assuming.
    const onChange = async (_changes, area) => {
      if (area === 'session' && (await hasKeypair())) finish(true);
    };
    chrome.storage.onChanged.addListener(onChange);
    // Two minutes for the user to find the popup and type their passphrase.
    timer = setTimeout(() => finish(false), 120000);
    // Only prompt if the key didn't already land in the race window between the
    // caller's hasKeypair() check and this listener being registered.
    hasKeypair().then((already) => (already ? finish(true) : openUnlockPopup()));
  });

  return pendingUnlock;
}

/**
 * Ensure the private key is unlocked in the session before a signing or
 * key-reading operation. Distinguishes three states so the error is actionable:
 *   - unlocked (session key present) -> returns
 *   - locked (encrypted vault on disk, no session key) -> opens ONE unlock UI,
 *     waits for the user's single passphrase entry (shared across concurrent
 *     callers), then returns; only throws if the unlock times out
 *   - empty (no vault at all) -> throws a "generate or import" error
 */
async function ensureUnlocked () {
  if (await hasKeypair()) return;

  if (await hasVault()) {
    const unlocked = await awaitUnlock();
    if (unlocked && (await hasKeypair())) return;
    throw new Error('Podkey is locked. Open Podkey, unlock with your passphrase, and try again.');
  }
  throw new Error('No key in Podkey. Open the extension to generate or import a key first.');
}

/**
 * Best-effort: surface the popup so the user can unlock. Never throws — the
 * caller still rejects with the "locked" message if the window cannot open.
 */
function openUnlockPopup () {
  try {
    chrome.windows.create({
      url: 'popup/popup.html',
      type: 'popup',
      width: 400,
      height: 560,
      focused: true
    });
  } catch (e) {
    if (DEBUG) console.log('[Podkey] Could not open unlock popup:', e.message);
  }
}

/**
 * Get public key with user permission
 */
async function handleGetPublicKey (origin, _sender) {
  // Require an unlocked key (locked vault -> opens unlock UI; no key -> setup).
  await ensureUnlocked();

  // Check if origin is trusted
  const trusted = await isTrustedOrigin(origin);

  if (!trusted) {
    // Show permission prompt
    const allowed = await showPermissionPrompt(origin, 'read your public key');

    if (!allowed) {
      throw new Error('User denied permission');
    }

    // Trust this origin
    await addTrustedOrigin(origin);
  }

  // Get and return public key (ensure it's a string)
  const keypair = await getKeypair();
  if (!keypair || !keypair.publicKey || typeof keypair.publicKey !== 'string') {
    throw new Error('Invalid keypair format');
  }
  return String(keypair.publicKey);
}

/**
 * Sign event with user permission
 */
async function handleSignEvent (event, origin, _sender) {
  // Require an unlocked key (locked vault -> opens unlock UI; no key -> setup).
  await ensureUnlocked();

  const keypair = await getKeypair();

  // A trusted origin signs without a prompt — the same trust model already used
  // by GET_PUBLIC_KEY and nip44.{encrypt,decrypt} (decrypting DMs is strictly
  // more sensitive than signing, and is silent for trusted origins). An
  // untrusted origin always prompts, and approving it establishes revocable
  // trust. The previous `&& autoSign && isSolidAuth` gate special-cased Solid
  // kind-27235 and made Podkey unusable as a general NIP-07 signer — a normal
  // client (kind 0/1/10002/22242…) re-prompted on every page load. isSolidAuth
  // now only tunes the wording of the first-contact prompt.
  const isSolidAuth = event.kind === 27235;
  const trusted = await isTrustedOrigin(origin);

  let shouldSign = trusted;

  if (!shouldSign) {
    // Show signing prompt with event preview
    const actionLabel = isSolidAuth ? 'sign a Solid authentication event' : `sign an event (kind ${event.kind})`;
    const previewData = JSON.stringify({
      kind: event.kind,
      content: (event.content || '').substring(0, 200),
      tags: (event.tags || []).length
    });
    const allowed = await showPermissionPrompt(origin, actionLabel, previewData);

    if (!allowed) {
      throw new Error('User denied signing');
    }

    // Trust this origin if not already trusted
    if (!trusted) {
      await addTrustedOrigin(origin);
    }
  }

  // Sign the event
  const signedEvent = await signEvent(event, keypair.privateKey);

  if (DEBUG) console.log('[Podkey] Event signed:', signedEvent.id.substring(0, 16) + '...');

  // Ensure event structure is correct (tags should be array, content should be string)
  // Preserve original event structure but ensure required fields are correct types
  return {
    ...signedEvent,
    kind: Number(signedEvent.kind),
    created_at: Number(signedEvent.created_at),
    tags: Array.isArray(signedEvent.tags) ? signedEvent.tags : [],
    content: String(signedEvent.content || '')
  };
}

/**
 * Resolve the user's keypair for an encryption request, gating on origin
 * trust exactly the way GET_PUBLIC_KEY / SIGN_EVENT do. The raw private key
 * never leaves the background service worker — only ciphertext/plaintext or a
 * conversation key is returned to the page.
 *
 * @param {string} origin - requesting page origin
 * @param {string} action - human-readable action for the permission prompt
 * @returns {Promise<{privateKey: string, publicKey: string}>}
 */
async function resolveKeypairForEncryption (origin, action) {
  // Require an unlocked key (locked vault -> opens unlock UI; no key -> setup).
  await ensureUnlocked();

  const trusted = await isTrustedOrigin(origin);
  if (!trusted) {
    const allowed = await showPermissionPrompt(origin, action);
    if (!allowed) {
      throw new Error('User denied permission');
    }
    await addTrustedOrigin(origin);
  }

  const keypair = await getKeypair();
  if (!keypair || typeof keypair.privateKey !== 'string') {
    throw new Error('Invalid keypair format');
  }
  return keypair;
}

/**
 * NIP-44 (v2) encrypt: encrypt plaintext for a peer pubkey.
 * @param {string} peerPubkey - 64-char hex peer public key
 * @param {string} plaintext - message to encrypt
 * @param {string} origin - requesting page origin
 * @returns {Promise<string>} base64 NIP-44 payload
 */
async function handleNip44Encrypt (peerPubkey, plaintext, origin) {
  if (typeof peerPubkey !== 'string' || typeof plaintext !== 'string') {
    throw new Error('nip44.encrypt requires (pubkey, plaintext) strings');
  }

  const keypair = await resolveKeypairForEncryption(origin, 'encrypt a message (NIP-44)');
  const conversationKey = getConversationKey(keypair.privateKey, peerPubkey);
  return nip44Encrypt(plaintext, conversationKey);
}

/**
 * NIP-44 (v2) decrypt: decrypt a base64 payload from a peer pubkey.
 * @param {string} peerPubkey - 64-char hex peer public key
 * @param {string} ciphertext - base64 NIP-44 payload
 * @param {string} origin - requesting page origin
 * @returns {Promise<string>} decrypted plaintext
 */
async function handleNip44Decrypt (peerPubkey, ciphertext, origin) {
  if (typeof peerPubkey !== 'string' || typeof ciphertext !== 'string') {
    throw new Error('nip44.decrypt requires (pubkey, ciphertext) strings');
  }

  const keypair = await resolveKeypairForEncryption(origin, 'decrypt a message (NIP-44)');
  const conversationKey = getConversationKey(keypair.privateKey, peerPubkey);
  return nip44Decrypt(ciphertext, conversationKey);
}

/**
 * NIP-44 (v2) conversation key derivation (hex). Some apps call this sub-API to
 * cache the key client-side; we still derive it in the background so the raw
 * private key stays here.
 * @param {string} peerPubkey - 64-char hex peer public key
 * @param {string} origin - requesting page origin
 * @returns {Promise<string>} 64-char hex conversation key
 */
async function handleNip44GetConversationKey (peerPubkey, origin) {
  if (typeof peerPubkey !== 'string') {
    throw new Error('nip44.getConversationKey requires a pubkey string');
  }

  const keypair = await resolveKeypairForEncryption(origin, 'derive a NIP-44 conversation key');
  const conversationKey = getConversationKey(keypair.privateKey, peerPubkey);
  return nip44BytesToHex(conversationKey);
}

/**
 * Generate a new keypair, seal it under the passphrase, and unlock the session.
 */
async function handleGenerateKeypair (passphrase) {
  try {
    const keypair = await generateKeypair();
    await createVault(keypair.privateKey, passphrase);     // encrypted at rest
    await storeKeypair(keypair.privateKey, keypair.publicKey); // unlocked session
    if (DEBUG) console.log('[Podkey] Keypair generated, sealed, and unlocked');

    return {
      publicKey: keypair.publicKey,
      did: `did:nostr:${keypair.publicKey}`
    };
  } catch (error) {
    console.error('[Podkey] Error generating keypair:', error);
    throw error;
  }
}

/**
 * Import an existing private key, seal it under the passphrase, and unlock.
 */
async function handleImportKeypair (privateKey, passphrase) {
  // Accept either raw 64-char hex or an `nsec1…` (NIP-19) key. Most Nostr apps
  // display keys in nsec form, so an existing-key import must handle it inline —
  // convert to Podkey's canonical hex without treating the format as an error.
  // `normalizeSecretKeyToHex` throws a neutral "Invalid key" on anything else.
  const hexKey = normalizeSecretKeyToHex(privateKey);

  // Derive public key (also validates the scalar is a usable secp256k1 key).
  const publicKey = getPublicKey(hexKey);

  await createVault(hexKey, passphrase);     // encrypted at rest (validates passphrase)
  await storeKeypair(hexKey, publicKey);     // unlocked session

  if (DEBUG) console.log('[Podkey] Keypair imported and sealed');

  return {
    publicKey,
    did: `did:nostr:${publicKey}`
  };
}

/**
 * Unlock the vault: decrypt the private key into the session with the
 * passphrase. Throws 'Incorrect passphrase' on a bad passphrase.
 */
async function handleUnlockVault (passphrase) {
  const privateKey = await unlockVault(passphrase);   // throws on wrong passphrase
  const publicKey = getPublicKey(privateKey);
  await storeKeypair(privateKey, publicKey);          // populate session cache

  if (DEBUG) console.log('[Podkey] Vault unlocked');

  return {
    publicKey,
    did: `did:nostr:${publicKey}`
  };
}

/**
 * Lock the vault: drop the in-memory key but keep the encrypted vault on disk.
 */
async function handleLockVault () {
  await clearSessionKey();
  if (DEBUG) console.log('[Podkey] Vault locked');
  return { ok: true };
}

/**
 * Get keypair status as one of three states the popup routes on:
 *   - 'unlocked' — session key present (returns publicKey/did)
 *   - 'locked'   — encrypted vault on disk, session cleared (returns the stored
 *                  publicKey so the unlock screen can show the identity)
 *   - 'none'     — no vault at all (show setup)
 */
async function handleGetKeypairStatus () {
  if (await hasKeypair()) {
    const keypair = await getKeypair();
    return {
      state: 'unlocked',
      exists: true,
      publicKey: keypair.publicKey,
      did: `did:nostr:${keypair.publicKey}`
    };
  }

  if (await hasVault()) {
    const publicKey = await getStoredPublicKey();
    return {
      state: 'locked',
      exists: true,
      publicKey: publicKey || null,
      did: publicKey ? `did:nostr:${publicKey}` : null
    };
  }

  return { state: 'none', exists: false };
}

/**
 * Show permission prompt to user via a popup window.
 * Opens popup/approve.html and waits for the user to approve or deny.
 * Auto-denies after 60 seconds if no response.
 * @param {string} origin - The requesting origin
 * @param {string} action - Human-readable description of the action
 * @param {string} [eventPreview] - Optional preview of the event data
 * @returns {Promise<boolean>} True if user approved
 */
async function showPermissionPrompt (origin, action, eventPreview) {
  const requestId = crypto.randomUUID();

  return new Promise((resolve) => {
    pendingApprovals.set(requestId, resolve);

    // Auto-deny after 60 seconds if no response
    const timeout = setTimeout(() => {
      if (pendingApprovals.has(requestId)) {
        pendingApprovals.delete(requestId);
        console.log(`[Podkey] Signing request ${requestId} timed out, auto-denying`);
        resolve(false);
      }
    }, 60000);

    // Clean up timeout when resolved normally
    const originalResolve = resolve;
    pendingApprovals.set(requestId, (approved) => {
      clearTimeout(timeout);
      originalResolve(approved);
    });

    const params = new URLSearchParams({
      id: requestId,
      origin: origin || 'Unknown',
      action: action || 'sign',
      preview: eventPreview || ''
    });

    chrome.windows.create({
      url: `popup/approve.html?${params.toString()}`,
      type: 'popup',
      width: 420,
      height: 380,
      focused: true
    });
  });
}

/**
 * Encode signed event to Authorization header value
 * @param {object} signedEvent - Signed Nostr event
 * @returns {string} Base64-encoded event for Authorization header
 */
function encodeNip98Header (signedEvent) {
  const eventJson = JSON.stringify(signedEvent);
  // Use btoa for base64 encoding (available in service workers)
  return btoa(eventJson);
}


/**
 * Create NIP-98 auth header for a request (called from content script)
 * @param {string} url - Request URL
 * @param {string} method - HTTP method
 * @param {string|ArrayBuffer|Blob|null} body - Request body
 * @returns {Promise<string>} Authorization header value
 */
/**
 * Check if an origin is likely a Solid server
 * @param {string} origin - Origin to check
 * @returns {boolean}
 */
function isLikelySolidServer (origin) {
  let hostname;
  try {
    hostname = new URL(origin).hostname;
  } catch {
    return false;
  }

  const trustedHosts = [
    'solid.social',
    'solidcommunity.net',
    'inrupt.net',
    'solidweb.org'
  ];

  return trustedHosts.some(trusted =>
    hostname === trusted || hostname.endsWith('.' + trusted)
  );
}

async function createNip98AuthHeader (url, method, body = null, bodyHash = null) {
  try {
    // Check if we should add auth
    const origin = new URL(url).origin;
    const trusted = await isTrustedOrigin(origin);
    const autoSign = await getAutoSign();
    const keyExists = await hasKeypair();
    const isSolid = isLikelySolidServer(origin);

    if (DEBUG) console.log('[Podkey] NIP-98 auth check:', { url, origin, keyExists, trusted, autoSign, isSolid });

    if (!keyExists) {
      if (DEBUG) console.log('[Podkey] No keypair found, skipping NIP-98 auth');
      return null;
    }

    // For Solid servers, auto-trust on first use if auto-sign is enabled
    if (!trusted && isSolid && autoSign) {
      if (DEBUG) console.log('[Podkey] Auto-trusting Solid server:', origin);
      await addTrustedOrigin(origin);
    } else if (!trusted) {
      if (DEBUG) console.log('[Podkey] Origin not trusted, skipping NIP-98 auth');
      return null;
    }

    if (!autoSign) {
      if (DEBUG) console.log('[Podkey] Auto-sign disabled, skipping NIP-98 auth');
      return null;
    }

    // Prefer a body hash computed in the page context (the only place where
    // FormData / URLSearchParams / streamed bodies survive intact). Fall back
    // to hashing here for body types that cross the message channel losslessly.
    let resolvedBodyHash = typeof bodyHash === 'string' ? bodyHash : '';
    if (!resolvedBodyHash && body) {
      if (typeof body === 'string') {
        resolvedBodyHash = bytesToHex(sha256(new TextEncoder().encode(body)));
      } else if (body instanceof ArrayBuffer) {
        resolvedBodyHash = bytesToHex(sha256(new Uint8Array(body)));
      } else if (body instanceof Blob) {
        resolvedBodyHash = bytesToHex(sha256(new Uint8Array(await body.arrayBuffer())));
      }
    }

    // Always create a fresh signed event (no caching -- reusing signed events
    // causes replay issues and servers with replay protection reject them).
    // created_at has 1-second resolution, so a random nonce tag guarantees a
    // distinct event id for repeated identical requests within the same second.
    const event = {
      kind: 27235,
      content: '',
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['u', url],
        ['method', method],
        ['nonce', bytesToHex(crypto.getRandomValues(new Uint8Array(16)))]
      ]
    };

    if (resolvedBodyHash) {
      event.tags.push(['payload', resolvedBodyHash]);
    }

    const keypair = await getKeypair();
    const signedEvent = await signEvent(event, keypair.privateKey);

    if (DEBUG) {
      console.log('[Podkey] NIP-98 event:', JSON.stringify(signedEvent));
      console.log('[Podkey] Public key (did:nostr):', `did:nostr:${keypair.publicKey}`);
    }

    return `Nostr ${encodeNip98Header(signedEvent)}`;
  } catch (error) {
    console.error('[Podkey] Error creating NIP-98 auth header:', error);
    return null;
  }
}

// Note: Blocking webRequest listeners require webRequestBlocking permission,
// which is deprecated in Manifest V3 and only available for enterprise extensions.
// Instead, we use JavaScript-level interception via content scripts.
// See src/injected.js for fetch/XMLHttpRequest interception.

if (DEBUG) console.log('[Podkey] NIP-98 auto-auth: Using JavaScript-level interception (see injected.js)');
