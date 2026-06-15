/**
 * Podkey - Content Script
 * Bridges between injected window.nostr and background script.
 *
 * Fetch/XHR interception for NIP-98 auth headers is handled exclusively
 * by src/nip98-interceptor.js (injected into the page context below).
 * This content script only relays messages between the page and the
 * extension background via CustomEvents.
 */

// Inject NIP-98 interceptor FIRST (must run before any page code)
const interceptorScript = document.createElement('script');
interceptorScript.src = chrome.runtime.getURL('src/nip98-interceptor.js');
interceptorScript.onload = function () {
  this.remove();
};
interceptorScript.onerror = function () {
  console.error('[Podkey] Failed to load nip98-interceptor.js');
};
(document.head || document.documentElement).appendChild(interceptorScript);

// Listen for NIP-98 auth requests from page context. The request body never
// crosses this boundary -- the page context computes its SHA-256 (the only
// place FormData / URLSearchParams / streamed bodies survive intact) and sends
// only the hex digest for the NIP-98 `payload` tag.
window.addEventListener('podkey-nip98-request', async (event) => {
  const { id, url, method, bodyHash } = event.detail;

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'CREATE_NIP98_AUTH_HEADER',
      url,
      method,
      bodyHash
    });

    if (chrome.runtime.lastError) {
      throw new Error(chrome.runtime.lastError.message);
    }

    // Send response back to page context
    window.dispatchEvent(new CustomEvent('podkey-nip98-response', {
      detail: {
        id,
        result: response || null
      }
    }));
  } catch (error) {
    console.error('[Podkey] Error handling NIP-98 request:', error);
    window.dispatchEvent(new CustomEvent('podkey-nip98-response', {
      detail: {
        id,
        result: null
      }
    }));
  }
});

// Inject the nostr provider script into the page
const script = document.createElement('script');
script.src = chrome.runtime.getURL('src/nostr-provider.js');
script.onload = function () {
  this.remove();
};
script.onerror = function () {
  console.error('[Podkey] Failed to load nostr-provider.js');
};
(document.head || document.documentElement).appendChild(script);

// Allowed message types that can be forwarded to the background script
const ALLOWED_TYPES = new Set([
  'GET_PUBLIC_KEY',
  'SIGN_EVENT',
  'NIP44_ENCRYPT',
  'NIP44_DECRYPT'
]);

// Listen for requests from the injected script (NIP-07 relay)
window.addEventListener('podkey-request', async (event) => {
  const { id, type, ...data } = event.detail;

  console.log('[Podkey] Received request:', type, 'from page');

  if (!ALLOWED_TYPES.has(type)) {
    console.warn('[Podkey] Rejected unknown request type:', type);
    window.dispatchEvent(new CustomEvent('podkey-response', {
      detail: { id, error: 'Unknown request type' }
    }));
    return;
  }

  // Only forward known safe fields per message type
  const safeData = {};
  if (type === 'SIGN_EVENT' && data.event) {
    safeData.event = data.event;
  } else if (type === 'NIP44_ENCRYPT' || type === 'NIP44_DECRYPT') {
    if (data.pubkey) safeData.pubkey = String(data.pubkey);
    if (data.plaintext !== undefined) safeData.plaintext = String(data.plaintext || '');
    if (data.ciphertext !== undefined) safeData.ciphertext = String(data.ciphertext);
  }

  try {
    // Forward to background script with only validated fields
    const response = await chrome.runtime.sendMessage({
      type,
      ...safeData,
      origin: window.location.origin
    });

    // Check for Chrome extension errors
    if (chrome.runtime.lastError) {
      throw new Error(chrome.runtime.lastError.message);
    }

    // Handle undefined/null responses
    if (response === undefined || response === null) {
      throw new Error('No response from extension');
    }

    // Check if response has an error
    if (response && typeof response === 'object' && response.error) {
      console.error('[Podkey] Background error:', response.error);
      window.dispatchEvent(new CustomEvent('podkey-response', {
        detail: {
          id,
          error: response.error
        }
      }));
      return;
    }

    // Send response back to page
    // Ensure we pass the response directly (could be string, object, etc.)
    window.dispatchEvent(new CustomEvent('podkey-response', {
      detail: {
        id,
        result: response
      }
    }));
  } catch (error) {
    console.error('[Podkey] Error handling request:', error);
    // Send error back to page
    window.dispatchEvent(new CustomEvent('podkey-response', {
      detail: {
        id,
        error: error.message || String(error)
      }
    }));
  }
});

console.log('[Podkey] Content script loaded');
