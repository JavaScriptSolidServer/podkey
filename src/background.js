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
 * Create NIP-98 authentication event for an HTTP request
 * @param {object} requestDetails - Chrome webRequest details
 * @returns {Promise<object>} Unsigned NIP-98 event
 */
async function createNip98AuthEvent (requestDetails) {
  const event = {
    kind: 27235,
    content: '',
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['u', requestDetails.url], // Full URL including query params
      ['method', requestDetails.method]
    ]
  };

  // If request has body, add payload tag with SHA-256 hash
  if (requestDetails.requestBody) {
    const bodyHash = await hashRequestBody(requestDetails.requestBody);
    event.tags.push(['payload', bodyHash]);
  }

  return event;
}

/**
 * Hash request body for NIP-98 payload tag
 * @param {object} requestBody - Chrome webRequest requestBody
 * @returns {Promise<string>} SHA-256 hash as hex string
 */
async function hashRequestBody (requestBody) {
  let bodyBytes;

  if (requestBody.raw) {
    // ArrayBuffer[] format from Chrome
    const chunks = requestBody.raw;
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.bytes.byteLength, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(new Uint8Array(chunk.bytes), offset);
      offset += chunk.bytes.byteLength;
    }
    bodyBytes = combined;
  } else if (requestBody.formData) {
    // FormData - convert to string representation
    const formDataStr = JSON.stringify(requestBody.formData);
    bodyBytes = new TextEncoder().encode(formDataStr);
  } else {
    // Fallback: treat as empty
    bodyBytes = new Uint8Array(0);
  }

  const hash = sha256(bodyBytes);
  return bytesToHex(hash);
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
 * Check if request should have NIP-98 auth added
 * @param {object} requestDetails - Chrome webRequest details
 * @returns {Promise<boolean>}
 */
async function shouldAddNip98Auth (requestDetails) {
  // Check if keypair exists
  const keyExists = await hasKeypair();
  if (!keyExists) {
    return false;
  }

  // Check if origin is trusted
  const origin = new URL(requestDetails.url).origin;
  const trusted = await isTrustedOrigin(origin);
  if (!trusted) {
    return false;
  }

  // Check if auto-sign is enabled
  const autoSign = await getAutoSign();
  if (!autoSign) {
    return false;
  }

  // Don't add auth if request already has Authorization header (unless it's a retry)
  const hasAuth = requestDetails.requestHeaders?.some(
    h => h.name.toLowerCase() === 'authorization'
  );
  if (hasAuth && !retryState.has(requestDetails.requestId)) {
    return false;
  }

  return true;
}

/**
 * Intercept requests and add NIP-98 auth if needed
 * @param {object} details - Chrome webRequest details
 * @returns {object|undefined} Modified request headers or undefined
 */
async function interceptRequest (details) {
  try {
    // Only process XMLHttpRequest and fetch requests
    if (!['xmlhttprequest', 'main_frame', 'sub_frame'].includes(details.type)) {
      return;
    }

    const shouldAuth = await shouldAddNip98Auth(details);
    if (!shouldAuth) {
      return;
    }

    // Check cache first
    const bodyHash = details.requestBody ? await hashRequestBody(details.requestBody) : '';
    const cacheKey = `${details.url}:${details.method}:${bodyHash}`;
    const cached = nip98Cache.get(cacheKey);

    let signedEvent;
    if (cached && cached.expires > Date.now()) {
      // Use cached event
      signedEvent = cached.event;
      console.log('[Podkey] Using cached NIP-98 auth event');
    } else {
      // Create and sign new event
      const event = await createNip98AuthEvent(details);
      const keypair = await getKeypair();
      signedEvent = await signEvent(event, keypair.privateKey);

      // Cache the signed event
      nip98Cache.set(cacheKey, {
        event: signedEvent,
        expires: Date.now() + CACHE_TTL
      });

      console.log('[Podkey] Created and signed NIP-98 auth event for', details.url);
    }

    // Encode to Authorization header
    const authHeader = encodeNip98Header(signedEvent);

    // Add or replace Authorization header
    const headers = details.requestHeaders || [];
    const authIndex = headers.findIndex(h => h.name.toLowerCase() === 'authorization');

    if (authIndex >= 0) {
      headers[authIndex].value = `Nostr ${authHeader}`;
    } else {
      headers.push({
        name: 'Authorization',
        value: `Nostr ${authHeader}`
      });
    }

    return { requestHeaders: headers };
  } catch (error) {
    console.error('[Podkey] Error intercepting request:', error);
    // Don't block the request if auth fails
    return;
  }
}

/**
 * Handle 401 response - create auth and retry
 * @param {object} details - Chrome webRequest details
 * @returns {object|undefined} Modified response or undefined
 */
async function handle401Response (details) {
  // Only retry on 401 Unauthorized
  if (details.statusCode !== 401) {
    return;
  }

  // Prevent infinite retry loops
  if (retryState.has(details.requestId)) {
    console.log('[Podkey] Already retried this request, skipping');
    return;
  }

  try {
    // Check if we should auto-auth this origin
    const origin = new URL(details.url).origin;
    const trusted = await isTrustedOrigin(origin);
    const autoSign = await getAutoSign();

    if (!trusted || !autoSign) {
      console.log('[Podkey] Origin not trusted or auto-sign disabled, not retrying');
      return;
    }

    // Mark as retrying
    retryState.set(details.requestId, true);

    // Create NIP-98 auth event
    const event = await createNip98AuthEvent({
      url: details.url,
      method: details.method,
      requestBody: details.requestBody
    });

    const keypair = await getKeypair();
    const signedEvent = await signEvent(event, keypair.privateKey);
    const authHeader = encodeNip98Header(signedEvent);

    console.log('[Podkey] 401 detected, created NIP-98 auth for retry:', details.url);

    // Retry the request with auth header
    // Note: Chrome webRequest API doesn't support retrying directly
    // The page/script needs to retry, but we can log the auth header
    // For now, we'll rely on the onBeforeSendHeaders interceptor for the retry
    // This is a limitation - we'd need to use fetch() API to actually retry

    // Clean up retry state after a delay
    setTimeout(() => {
      retryState.delete(details.requestId);
    }, 5000);
  } catch (error) {
    console.error('[Podkey] Error handling 401 response:', error);
    retryState.delete(details.requestId);
  }
}

// Set up webRequest listeners for NIP-98 auto-auth
chrome.webRequest.onBeforeSendHeaders.addListener(
  interceptRequest,
  {
    urls: ['<all_urls>'],
    types: ['xmlhttprequest', 'main_frame', 'sub_frame']
  },
  ['requestHeaders', 'blocking']
);

chrome.webRequest.onHeadersReceived.addListener(
  handle401Response,
  {
    urls: ['<all_urls>'],
    types: ['xmlhttprequest', 'main_frame', 'sub_frame']
  },
  ['responseHeaders']
);

console.log('[Podkey] NIP-98 auto-auth listeners registered');
