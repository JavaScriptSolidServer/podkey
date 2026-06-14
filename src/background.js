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
  isTrustedOrigin,
  addTrustedOrigin,
  getAutoSign
} from './storage.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

console.log('[Podkey] Background service worker started');

// NIP-98 events are always created fresh to avoid replay issues

// Track retry state to prevent infinite loops: key = requestId, value = true
const retryState = new Map();

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
      console.log('[Podkey] Message handled successfully:', message.type, result);
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

  console.log('[Podkey] Message received:', type, 'from', origin || 'popup');

  switch (type) {
    case 'GET_PUBLIC_KEY':
      return await handleGetPublicKey(origin, sender);

    case 'SIGN_EVENT':
      return await handleSignEvent(message.event, origin, sender);

    case 'GENERATE_KEYPAIR':
      return await handleGenerateKeypair();

    case 'IMPORT_KEYPAIR':
      return await handleImportKeypair(message.privateKey);

    case 'GET_KEYPAIR_STATUS':
      return await handleGetKeypairStatus();

    case 'GET_RELAYS':
      // TODO: Implement relay management
      return {};

    case 'NIP04_ENCRYPT':
    case 'NIP04_DECRYPT':
      throw new Error('NIP-04 encryption not yet implemented');

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
        message.body
      );

    default:
      throw new Error(`Unknown message type: ${type}`);
  }
}

/**
 * Get public key with user permission
 */
async function handleGetPublicKey (origin, sender) {
  // Check if keypair exists
  const keyExists = await hasKeypair();
  if (!keyExists) {
    throw new Error('No keypair found. Please generate or import a key first.');
  }

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
async function handleSignEvent (event, origin, sender) {
  // Check if keypair exists
  const keyExists = await hasKeypair();
  if (!keyExists) {
    throw new Error('No keypair found. Please generate or import a key first.');
  }

  const keypair = await getKeypair();

  // Check if this is a Solid auth event (kind 27235) - auto-sign if trusted
  const isSolidAuth = event.kind === 27235;
  const trusted = await isTrustedOrigin(origin);
  const autoSign = await getAutoSign();

  let shouldSign = trusted && autoSign && isSolidAuth;

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

  console.log('[Podkey] Event signed:', signedEvent.id.substring(0, 16) + '...');

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
  const keyExists = await hasKeypair();
  if (!keyExists) {
    throw new Error('No keypair found. Please generate or import a key first.');
  }

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
 * Generate new keypair
 */
async function handleGenerateKeypair () {
  try {
    console.log('[Podkey] Starting keypair generation...');
    const keypair = await generateKeypair();
    console.log('[Podkey] Keypair generated:', {
      privateKeyLength: keypair.privateKey.length,
      publicKeyLength: keypair.publicKey.length
    });

    await storeKeypair(keypair.privateKey, keypair.publicKey);
    console.log('[Podkey] Keypair stored');

    const result = {
      publicKey: keypair.publicKey,
      did: `did:nostr:${keypair.publicKey}`
    };

    console.log('[Podkey] Returning result:', result);
    return result;
  } catch (error) {
    console.error('[Podkey] Error generating keypair:', error);
    throw error;
  }
}

/**
 * Import existing keypair
 */
async function handleImportKeypair (privateKey) {
  // Validate private key format
  if (!privateKey || privateKey.length !== 64) {
    throw new Error('Private key must be 64-char hex');
  }

  if (!/^[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error('Private key must be valid hexadecimal');
  }

  // Derive public key
  const publicKey = getPublicKey(privateKey);

  // Store keypair
  await storeKeypair(privateKey, publicKey);

  console.log('[Podkey] Keypair imported');

  return {
    publicKey,
    did: `did:nostr:${publicKey}`
  };
}

/**
 * Get keypair status
 */
async function handleGetKeypairStatus () {
  const exists = await hasKeypair();

  if (!exists) {
    return { exists: false };
  }

  const keypair = await getKeypair();

  return {
    exists: true,
    publicKey: keypair.publicKey,
    did: `did:nostr:${keypair.publicKey}`
  };
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
 * Format event for display in prompt
 */
function formatEventForPrompt (event) {
  const lines = [];
  lines.push(`Kind: ${event.kind}`);

  if (event.tags && event.tags.length > 0) {
    lines.push(`Tags: ${event.tags.length}`);
    event.tags.slice(0, 3).forEach(tag => {
      lines.push(`  [${tag.join(', ')}]`);
    });
  }

  if (event.content) {
    const preview = event.content.substring(0, 100);
    lines.push(`Content: ${preview}${event.content.length > 100 ? '...' : ''}`);
  }

  return lines.join('\n');
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

async function createNip98AuthHeader (url, method, body = null) {
  try {
    // Check if we should add auth
    const origin = new URL(url).origin;
    const trusted = await isTrustedOrigin(origin);
    const autoSign = await getAutoSign();
    const keyExists = await hasKeypair();
    const isSolid = isLikelySolidServer(origin);

    console.log('[Podkey] NIP-98 auth check:', {
      url,
      origin,
      keyExists,
      trusted,
      autoSign,
      isSolid
    });

    if (!keyExists) {
      console.log('[Podkey] No keypair found, skipping NIP-98 auth');
      return null;
    }

    // For Solid servers, auto-trust on first use if auto-sign is enabled
    if (!trusted && isSolid && autoSign) {
      console.log('[Podkey] Auto-trusting Solid server:', origin);
      await addTrustedOrigin(origin);
    } else if (!trusted) {
      console.log('[Podkey] Origin not trusted, skipping NIP-98 auth');
      return null;
    }

    if (!autoSign) {
      console.log('[Podkey] Auto-sign disabled, skipping NIP-98 auth');
      return null;
    }

    // Hash body if present
    let bodyHash = '';
    if (body) {
      if (typeof body === 'string') {
        bodyHash = bytesToHex(sha256(new TextEncoder().encode(body)));
      } else if (body instanceof ArrayBuffer) {
        bodyHash = bytesToHex(sha256(new Uint8Array(body)));
      } else if (body instanceof Blob) {
        const arrayBuffer = await body.arrayBuffer();
        bodyHash = bytesToHex(sha256(new Uint8Array(arrayBuffer)));
      }
    }

    // Always create a fresh signed event (no caching -- reusing signed events
    // causes replay issues and servers with replay protection reject duplicates)
    const event = {
      kind: 27235,
      content: '',
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['u', url],
        ['method', method]
      ]
    };

    if (bodyHash) {
      event.tags.push(['payload', bodyHash]);
    }

    const keypair = await getKeypair();
    const signedEvent = await signEvent(event, keypair.privateKey);

    console.log('[Podkey] Created and signed NIP-98 auth event for', url);
    console.log('[Podkey] NIP-98 event:', JSON.stringify(signedEvent, null, 2));
    console.log('[Podkey] Public key (did:nostr):', `did:nostr:${keypair.publicKey}`);

    const authHeader = `Nostr ${encodeNip98Header(signedEvent)}`;
    console.log('[Podkey] Authorization header (first 100 chars):', authHeader.substring(0, 100) + '...');
    return authHeader;
  } catch (error) {
    console.error('[Podkey] Error creating NIP-98 auth header:', error);
    return null;
  }
}

// Note: Blocking webRequest listeners require webRequestBlocking permission,
// which is deprecated in Manifest V3 and only available for enterprise extensions.
// Instead, we use JavaScript-level interception via content scripts.
// See src/injected.js for fetch/XMLHttpRequest interception.

console.log('[Podkey] NIP-98 auto-auth: Using JavaScript-level interception (see injected.js)');
