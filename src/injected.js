/**
 * Podkey - Content Script
 * Bridges between injected window.nostr and background script
 */

// Inject the nostr provider script into the page
const script = document.createElement('script');
script.src = chrome.runtime.getURL('src/nostr-provider.js');
script.onload = function() {
  this.remove();
};
(document.head || document.documentElement).appendChild(script);

// Listen for requests from the injected script
window.addEventListener('podkey-request', async (event) => {
  const { id, type, ...data } = event.detail;

  try {
    // Forward to background script
    const response = await chrome.runtime.sendMessage({
      type,
      ...data,
      origin: window.location.origin
    });

    // Send response back to page
    window.dispatchEvent(new CustomEvent('podkey-response', {
      detail: {
        id,
        result: response
      }
    }));
  } catch (error) {
    // Send error back to page
    window.dispatchEvent(new CustomEvent('podkey-response', {
      detail: {
        id,
        error: error.message
      }
    }));
  }
});

console.log('[Podkey] Content script loaded');
