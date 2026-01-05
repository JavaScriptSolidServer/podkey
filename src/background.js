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

console.log('[Podkey] Background service worker started');

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
  handleMessage(message, sender).then(sendResponse).catch(error => {
    sendResponse({ error: error.message });
  });

  return true; // Async response
});

/**
 * Handle incoming messages
 */
async function handleMessage(message, sender) {
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
async function handleGetPublicKey(origin, sender) {
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

  // Get and return public key
  const keypair = await getKeypair();
  return keypair.publicKey;
}

/**
 * Sign event with user permission
 */
async function handleSignEvent(event, origin, sender) {
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

  return signedEvent;
}

/**
 * Generate new keypair
 */
async function handleGenerateKeypair() {
  const keypair = await generateKeypair();
  await storeKeypair(keypair.privateKey, keypair.publicKey);

  console.log('[Podkey] New keypair generated');

  return {
    publicKey: keypair.publicKey,
    did: `did:nostr:${keypair.publicKey}`
  };
}

/**
 * Import existing keypair
 */
async function handleImportKeypair(privateKey) {
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
async function handleGetKeypairStatus() {
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
 */
async function showPermissionPrompt(origin, action) {
  // For MVP, use browser confirm dialog
  // TODO: Show nice UI popup instead
  return new Promise((resolve) => {
    const message = `${origin} wants to ${action}\n\nAllow this action?`;
    const result = confirm(message);
    resolve(result);
  });
}

/**
 * Format event for display in prompt
 */
function formatEventForPrompt(event) {
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
