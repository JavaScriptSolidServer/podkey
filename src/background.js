/**
 * Podkey - Background Service Worker
 * Coordinates key management, signing, and Solid auto-auth
 */

import { generateKeypair, signEvent, getPublicKey } from './crypto.js';
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

// NIP-98 auth event cache: key = `${url}:${method}:${bodyHash}`, value = { event, expires }
const nip98Cache = new Map();
const CACHE_TTL = 60000; // 60 seconds

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

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
    const allowed = await showPermissionPrompt(origin, 'share your public key');

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
    // Show signing prompt
    const eventPreview = formatEventForPrompt(event);
    const allowed = await showPermissionPrompt(
      origin,
      `sign this ${isSolidAuth ? 'Solid authentication' : 'event'}:\n\n${eventPreview}`
    );

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
 * Show permission prompt to user
 * Note: Service workers can't use confirm(), so we auto-approve for now
 * TODO: Implement proper UI using chrome.notifications or action badge
 */
async function showPermissionPrompt (origin, action) {
  // For now, auto-approve requests (service workers can't use confirm())
  // In production, this should show a notification or update the badge
  console.log(`[Podkey] Auto-approving: ${origin} wants to ${action}`);

  // TODO: Show notification using chrome.notifications API
  // For now, return true to auto-approve
  return true;

  // Future implementation:
  // return new Promise((resolve) => {
  //   chrome.notifications.create({
  //     type: 'basic',
  //     iconUrl: 'icons/128x128.png',
  //     title: 'Podkey Permission Request',
  //     message: `${origin} wants to ${action}`
  //   }, (notificationId) => {
  //     // Handle user response via notification buttons
  //   });
  // });
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
  // Common Solid server indicators
  const solidIndicators = [
    'solid.social',
    'solidcommunity.net',
    'inrupt.net',
    'solidweb.org',
    '/.well-known/solid'
  ];

  return solidIndicators.some(indicator => origin.includes(indicator));
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

    // Check cache
    const cacheKey = `${url}:${method}:${bodyHash}`;
    const cached = nip98Cache.get(cacheKey);

    let signedEvent;
    if (cached && cached.expires > Date.now()) {
      signedEvent = cached.event;
      console.log('[Podkey] Using cached NIP-98 auth event');
    } else {
      // Create and sign event
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
      signedEvent = await signEvent(event, keypair.privateKey);

      // Cache
      nip98Cache.set(cacheKey, {
        event: signedEvent,
        expires: Date.now() + CACHE_TTL
      });

      console.log('[Podkey] Created and signed NIP-98 auth event for', url);
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

console.log('[Podkey] NIP-98 auto-auth: Using JavaScript-level interception (see injected.js)');
