/**
 * Podkey - Content Script
 * Bridges between injected window.nostr and background script
 */

// CRITICAL: Set up fetch/XHR interception IMMEDIATELY, synchronously
// This must run before ANY other code, including page scripts
(function setupInterceptionImmediately () {
  'use strict';

  // Store original functions
  const originalFetch = window.fetch;
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  // Helper to get auth header (will be async, but we'll handle that)
  let getAuthHeaderFn = null;

  // Set up the async auth header function (will be defined below)
  function setAuthHeaderFn (fn) {
    getAuthHeaderFn = fn;
  }

  // Intercept fetch - synchronous wrapper, async implementation
  window.fetch = function (url, options = {}) {
    const urlString = typeof url === 'string' ? url : url.toString();
    console.log('[Podkey] 🔍 fetch() called:', urlString, options.method || 'GET');
    
    // If we have the auth function, use it
    if (getAuthHeaderFn) {
      console.log('[Podkey] Auth function available, adding header...');
      const promise = (async () => {
        try {
          const authHeader = await getAuthHeaderFn(url, options.method || 'GET', options.body);
          if (authHeader) {
            options = options || {};
            options.headers = options.headers || {};
            if (options.headers instanceof Headers) {
              options.headers.set('Authorization', authHeader);
              console.log('[Podkey] ✅ Added NIP-98 auth header (Headers)');
            } else {
              options.headers['Authorization'] = authHeader;
              console.log('[Podkey] ✅ Added NIP-98 auth header (object)');
            }
          } else {
            console.log('[Podkey] ⚠️ No auth header returned (will retry on 401)');
          }
        } catch (e) {
          console.error('[Podkey] Error in fetch interceptor:', e);
        }
        return originalFetch.call(this, url, options);
      })();
      
      // Handle 401 retry
      return promise.then(response => {
        if (response.status === 401 && getAuthHeaderFn) {
          console.log('[Podkey] 🔄 401 detected, retrying with auth...');
          return (async () => {
            try {
              const authHeader = await getAuthHeaderFn(url, options.method || 'GET', options.body);
              if (authHeader) {
                const retryOptions = { ...options };
                retryOptions.headers = retryOptions.headers || {};
                if (retryOptions.headers instanceof Headers) {
                  retryOptions.headers.set('Authorization', authHeader);
                } else {
                  retryOptions.headers['Authorization'] = authHeader;
                }
                console.log('[Podkey] 🔄 Retrying with NIP-98 auth...');
                const retryResponse = await originalFetch.call(this, url, retryOptions);
                if (retryResponse.status === 200 || retryResponse.status === 201) {
                  console.log('[Podkey] ✅✅ NIP-98 auth retry successful!');
                } else {
                  console.log('[Podkey] ⚠️ Retry still failed:', retryResponse.status);
                }
                return retryResponse;
              }
            } catch (e) {
              console.error('[Podkey] Error in 401 retry:', e);
            }
            return response;
          })();
        }
        return response;
      });
    }
    
    // Fallback if auth function not ready yet
    console.log('[Podkey] ⚠️ Auth function not ready yet, making request without auth');
    return originalFetch.call(this, url, options);
  };

  // Intercept XMLHttpRequest
  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    this._podkeyMethod = method;
    this._podkeyUrl = url;
    return originalXHROpen.apply(this, [method, url, ...args]);
  };

  XMLHttpRequest.prototype.send = function (body) {
    if (getAuthHeaderFn && this._podkeyUrl) {
      (async () => {
        try {
          const authHeader = await getAuthHeaderFn(this._podkeyUrl, this._podkeyMethod, body);
          if (authHeader) {
            this.setRequestHeader('Authorization', authHeader);
          }
        } catch (e) {
          console.error('[Podkey] Error in XHR interceptor:', e);
        }
      })();
    }
    return originalXHRSend.apply(this, [body]);
  };

  // Expose setter for the auth function
  window.__podkey_setAuthFn = setAuthHeaderFn;

  console.log('[Podkey] ✅ Synchronous interception setup complete');
})();

// Inject the nostr provider script into the page
const script = document.createElement('script');
script.src = chrome.runtime.getURL('src/nostr-provider.js');
script.onload = function () {
  this.remove();
};
(document.head || document.documentElement).appendChild(script);

// Listen for requests from the injected script
window.addEventListener('podkey-request', async (event) => {
  const { id, type, ...data } = event.detail;

  console.log('[Podkey] Received request:', type, 'from page');

  try {
    // Forward to background script
    const response = await chrome.runtime.sendMessage({
      type,
      ...data,
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

// NIP-98 auto-auth: Set up the async auth header function
// This connects to the synchronous interceptor above
(function setupAuthFunction () {
  console.log('[Podkey] Setting up NIP-98 auth function...');

  async function getNip98AuthHeader (url, method, body) {
    try {
      const urlString = typeof url === 'string' ? url : url.toString();
      console.log('[Podkey] Requesting NIP-98 auth header for:', urlString, method);

      const response = await chrome.runtime.sendMessage({
        type: 'CREATE_NIP98_AUTH_HEADER',
        url: urlString,
        method: method || 'GET',
        body: body
      });

      if (chrome.runtime.lastError) {
        console.error('[Podkey] Error from background script:', chrome.runtime.lastError.message);
        return null;
      }

      if (response) {
        console.log('[Podkey] ✅ Got NIP-98 auth header');
      } else {
        console.log('[Podkey] ❌ No NIP-98 auth header (origin not trusted, auto-sign disabled, or no keypair)');
      }

      return response || null;
    } catch (error) {
      console.error('[Podkey] Error getting NIP-98 auth header:', error);
      return null;
    }
  }

  // Connect the auth function to the synchronous interceptor
  if (window.__podkey_setAuthFn) {
    window.__podkey_setAuthFn(getNip98AuthHeader);
    console.log('[Podkey] ✅ Auth function connected');
  } else {
    console.error('[Podkey] ❌ Could not connect auth function - interceptor not ready');
  }
})();

console.log('[Podkey] Content script loaded with NIP-98 auto-auth interception');

// Error handling for script injection
script.onerror = function () {
  console.error('[Podkey] Failed to load nostr-provider.js');
};
