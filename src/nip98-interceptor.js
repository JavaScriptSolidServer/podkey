/**
 * NIP-98 HTTP Auth Interceptor
 * Injected into page context to intercept fetch/XHR requests
 */

(function () {
  'use strict';

  // Only inject once
  if (window.__podkey_nip98_intercepted) {
    return;
  }
  window.__podkey_nip98_intercepted = true;

  // Store original functions
  const originalFetch = window.fetch;
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  // Helper to get auth header from extension
  async function getNip98AuthHeader (url, method, body) {
    try {
      const urlString = typeof url === 'string' ? url : url.toString();

      // Send message to extension via custom event (content script will forward it)
      return new Promise((resolve) => {
        const eventId = Math.random().toString(36).substring(7);

        const handler = (event) => {
          if (event.detail.id === eventId) {
            window.removeEventListener('podkey-nip98-response', handler);
            resolve(event.detail.result || null);
          }
        };

        window.addEventListener('podkey-nip98-response', handler);

        // Request auth header
        window.dispatchEvent(new CustomEvent('podkey-nip98-request', {
          detail: {
            id: eventId,
            url: urlString,
            method: method || 'GET',
            body: body
          }
        }));

        // Timeout after 2 seconds
        setTimeout(() => {
          window.removeEventListener('podkey-nip98-response', handler);
          resolve(null);
        }, 2000);
      });
    } catch (error) {
      console.error('[Podkey] Error getting NIP-98 auth header:', error);
      return null;
    }
  }

  // Intercept fetch
  window.fetch = async function (url, options = {}) {
    const urlString = typeof url === 'string' ? url : url.toString();
    const method = options?.method || 'GET';
    console.log('[Podkey] 🔍 fetch() intercepted:', urlString, method);

    try {
      const authHeader = await getNip98AuthHeader(url, method, options?.body);
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
        console.log('[Podkey] ⚠️ No auth header (will retry on 401)');
      }
    } catch (error) {
      console.error('[Podkey] Error adding NIP-98 auth:', error);
    }

    const response = await originalFetch.call(this, url, options);

    // Handle 401 retry
    if (response.status === 401) {
      console.log('[Podkey] 🔄 401 detected, retrying with NIP-98 auth...');
      try {
        const authHeader = await getNip98AuthHeader(url, method, options?.body);
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
      } catch (error) {
        console.error('[Podkey] Error in 401 retry:', error);
      }
    }

    return response;
  };

  // Intercept XMLHttpRequest
  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    this._podkeyMethod = method;
    this._podkeyUrl = url;
    return originalXHROpen.apply(this, [method, url, ...args]);
  };

  XMLHttpRequest.prototype.send = async function (body) {
    if (this._podkeyUrl) {
      try {
        const authHeader = await getNip98AuthHeader(this._podkeyUrl, this._podkeyMethod, body);
        if (authHeader) {
          this.setRequestHeader('Authorization', authHeader);
          console.log('[Podkey] ✅ Added NIP-98 auth to XHR');
        }
      } catch (error) {
        console.error('[Podkey] Error adding NIP-98 auth to XHR:', error);
      }
    }
    return originalXHRSend.apply(this, [body]);
  };

  console.log('[Podkey] ✅ NIP-98 interceptor injected into page context');
})();
