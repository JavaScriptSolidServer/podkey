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
  const originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

  // Duplicate of src/auth-header-utils.js — keep in sync. The canonical
  // module is imported by unit tests; this copy runs in page context where
  // classic scripts can't use ESM imports. Build-time bundling to drop the
  // duplication is tracked in #7.
  function hasAuthorizationHeader (headers) {
    if (!headers) return false;
    if (typeof Headers !== 'undefined' && headers instanceof Headers) {
      return headers.has('authorization');
    }
    if (Array.isArray(headers)) {
      return headers.some((entry) =>
        Array.isArray(entry) && typeof entry[0] === 'string' &&
        entry[0].toLowerCase() === 'authorization'
      );
    }
    if (typeof headers === 'object') {
      for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === 'authorization') return true;
      }
    }
    return false;
  }

  // Per fetch spec, init.headers overrides Request.headers entirely — so
  // init.headers is authoritative when present. Only consult input.headers
  // when init omits the headers key.
  function fetchCallHasAuthorization (input, init) {
    if (init && Object.prototype.hasOwnProperty.call(init, 'headers')) {
      return hasAuthorizationHeader(init.headers);
    }
    if (typeof Request !== 'undefined' && input instanceof Request) {
      return hasAuthorizationHeader(input.headers);
    }
    return false;
  }

  function setAuthorizationOnOptions (options, value) {
    options.headers = options.headers || {};
    if (typeof Headers !== 'undefined' && options.headers instanceof Headers) {
      options.headers.set('Authorization', value);
    } else if (Array.isArray(options.headers)) {
      const normalized = new Headers(options.headers);
      normalized.set('Authorization', value);
      options.headers = normalized;
    } else {
      for (const key of Object.keys(options.headers)) {
        if (key.toLowerCase() === 'authorization') delete options.headers[key];
      }
      options.headers['Authorization'] = value;
    }
    return options.headers;
  }

  function normalizeFetchCall (input, init) {
    if (typeof Request !== 'undefined' && input instanceof Request) {
      return {
        url: input.url,
        method: init?.method || input.method || 'GET',
        body: init?.body
      };
    }
    return {
      url: typeof input === 'string' ? input : String(input),
      method: init?.method || 'GET',
      body: init?.body
    };
  }

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
    // Default-param `= {}` only applies for `undefined`; `fetch(url, null)`
    // passes null through. Coerce once so the rest of the wrapper can
    // assume an object.
    options = options || {};
    // Normalize once — handles fetch(url, init) and fetch(new Request(...))
    // so downstream signing sees the real URL/method, not "[object Request]".
    const { url: urlString, method, body } = normalizeFetchCall(url, options);
    console.log('[Podkey] 🔍 fetch() intercepted:', urlString, method);

    // Respect an Authorization header the page already set — on either
    // options.headers or a Request input (e.g. Solid-OIDC DPoP). Overwriting
    // would re-identify the request as Podkey's NIP-98 and break the page's
    // own auth. If that auth fails with 401, the retry path below still
    // injects NIP-98. See issue #5.
    const pageSetAuth = fetchCallHasAuthorization(url, options);

    if (!pageSetAuth) {
      try {
        const authHeader = await getNip98AuthHeader(urlString, method, body);
        if (authHeader) {
          setAuthorizationOnOptions(options, authHeader);
          console.log('[Podkey] ✅ Added NIP-98 auth header');
        } else {
          console.log('[Podkey] ⚠️ No auth header (will retry on 401)');
        }
      } catch (error) {
        console.error('[Podkey] Error adding NIP-98 auth:', error);
      }
    } else {
      console.log('[Podkey] ⏭️ Page already set Authorization — skipping injection');
    }

    const response = await originalFetch.call(this, url, options);

    // Handle 401 retry
    if (response.status === 401) {
      console.log('[Podkey] 🔄 401 detected, retrying with NIP-98 auth...');
      try {
        const authHeader = await getNip98AuthHeader(urlString, method, body);
        if (authHeader) {
          const retryOptions = { ...options };
          setAuthorizationOnOptions(retryOptions, authHeader);
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
    this._podkeyHasPageAuth = false;
    return originalXHROpen.apply(this, [method, url, ...args]);
  };

  // Track page-set Authorization on XHR so we don't overwrite it in send().
  // setRequestHeader auto-merges values per the XHR spec, but a merged
  // "DPoP xxx, Nostr yyy" still confuses servers that branch on scheme.
  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    if (typeof name === 'string' && name.toLowerCase() === 'authorization') {
      this._podkeyHasPageAuth = true;
    }
    return originalXHRSetRequestHeader.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = async function (body) {
    if (this._podkeyUrl && !this._podkeyHasPageAuth) {
      try {
        const authHeader = await getNip98AuthHeader(this._podkeyUrl, this._podkeyMethod, body);
        if (authHeader) {
          originalXHRSetRequestHeader.call(this, 'Authorization', authHeader);
          console.log('[Podkey] ✅ Added NIP-98 auth to XHR');
        }
      } catch (error) {
        console.error('[Podkey] Error adding NIP-98 auth to XHR:', error);
      }
    } else if (this._podkeyHasPageAuth) {
      console.log('[Podkey] ⏭️ Page set XHR Authorization — skipping injection');
    }
    return originalXHRSend.apply(this, [body]);
  };

  console.log('[Podkey] ✅ NIP-98 interceptor injected into page context');
})();
