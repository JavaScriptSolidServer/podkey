/**
 * Podkey - Content Script
 * Bridges between injected window.nostr and background script
 */

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

// NIP-98 auto-auth: Intercept fetch and XMLHttpRequest
(function interceptHttpRequests () {
  // Intercept fetch
  const originalFetch = window.fetch;
  window.fetch = async function (url, options = {}) {
    try {
      const authHeader = await getNip98AuthHeader(url, options.method || 'GET', options.body);
      if (authHeader) {
        options.headers = options.headers || {};
        if (options.headers instanceof Headers) {
          options.headers.set('Authorization', authHeader);
        } else {
          options.headers['Authorization'] = authHeader;
        }
      }
    } catch (error) {
      console.error('[Podkey] Error adding NIP-98 auth to fetch:', error);
    }

    const response = await originalFetch(url, options);

    // Handle 401 responses - retry with NIP-98 auth
    if (response.status === 401) {
      console.log('[Podkey] 401 detected, attempting NIP-98 auth retry for:', url);
      try {
        // Clone response to read body if needed, but for retry we'll make a new request
        const authHeader = await getNip98AuthHeader(url, options.method || 'GET', options.body);
        if (authHeader) {
          // Retry with auth
          const retryOptions = { ...options };
          retryOptions.headers = retryOptions.headers || {};

          // Handle Headers object
          if (retryOptions.headers instanceof Headers) {
            retryOptions.headers.set('Authorization', authHeader);
          } else if (retryOptions.headers instanceof Object) {
            retryOptions.headers['Authorization'] = authHeader;
          } else {
            retryOptions.headers = { 'Authorization': authHeader };
          }

          console.log('[Podkey] Retrying request with NIP-98 auth');
          const retryResponse = await originalFetch(url, retryOptions);

          if (retryResponse.status === 200 || retryResponse.status === 201) {
            console.log('[Podkey] ✅ NIP-98 auth successful!');
          } else {
            console.log('[Podkey] ⚠️ Retry still failed with status:', retryResponse.status);
          }

          return retryResponse;
        } else {
          console.log('[Podkey] No NIP-98 auth header available for retry');
        }
      } catch (error) {
        console.error('[Podkey] Error retrying fetch with NIP-98 auth:', error);
      }
    }

    return response;
  };

  // Intercept XMLHttpRequest
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    this._podkeyMethod = method;
    this._podkeyUrl = url;
    return originalOpen.apply(this, [method, url, ...args]);
  };

  XMLHttpRequest.prototype.send = async function (body) {
    try {
      const authHeader = await getNip98AuthHeader(this._podkeyUrl, this._podkeyMethod, body);
      if (authHeader) {
        this.setRequestHeader('Authorization', authHeader);
      }
    } catch (error) {
      console.error('[Podkey] Error adding NIP-98 auth to XHR:', error);
    }

    // Handle 401 responses
    this.addEventListener('load', async function () {
      if (this.status === 401) {
        try {
          const authHeader = await getNip98AuthHeader(this._podkeyUrl, this._podkeyMethod, body);
          if (authHeader) {
            // Retry with auth
            const retryXhr = new XMLHttpRequest();
            retryXhr.open(this._podkeyMethod, this._podkeyUrl);
            retryXhr.setRequestHeader('Authorization', authHeader);
            // Copy other headers if needed
            retryXhr.send(body);
            // Note: This is a simplified retry - in practice, you'd want to handle the response properly
          }
        } catch (error) {
          console.error('[Podkey] Error retrying XHR with NIP-98 auth:', error);
        }
      }
    });

    return originalSend.apply(this, [body]);
  };

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
        console.log('[Podkey] Got NIP-98 auth header');
      } else {
        console.log('[Podkey] No NIP-98 auth header (origin not trusted, auto-sign disabled, or no keypair)');
      }

      return response || null;
    } catch (error) {
      console.error('[Podkey] Error getting NIP-98 auth header:', error);
      return null;
    }
  }
})();

console.log('[Podkey] Content script loaded with NIP-98 auto-auth interception');

// Error handling for script injection
script.onerror = function () {
  console.error('[Podkey] Failed to load nostr-provider.js');
};
