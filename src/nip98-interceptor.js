/**
 * NIP-98 HTTP Auth Interceptor
 * Injected into page context to intercept fetch/XHR requests
 */

(function () {
  'use strict';

  // Set to true for verbose request-flow logging. Off by default; this script
  // never logs the Authorization header value or any token.
  const DEBUG = false;

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

  // Compute the NIP-98 `payload` body hash here in the page context, where the
  // body object is still intact (FormData / URLSearchParams / Blob cannot be
  // structured-cloned to the background service worker faithfully). Returns the
  // hex SHA-256, or '' when there is no hashable body. FormData is intentionally
  // unsupported: NIP-98 does not define a canonical hash for multipart bodies.
  async function bodyToHashHex (body) {
    if (body === undefined || body === null || body === '') return '';
    let bytes;
    if (typeof body === 'string') {
      bytes = new TextEncoder().encode(body);
    } else if (body instanceof URLSearchParams) {
      bytes = new TextEncoder().encode(body.toString());
    } else if (body instanceof Blob) {
      bytes = new Uint8Array(await body.arrayBuffer());
    } else if (body instanceof ArrayBuffer) {
      bytes = new Uint8Array(body);
    } else if (ArrayBuffer.isView(body)) {
      bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    } else {
      return '';
    }
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
  }

  // Helper to get auth header from extension
  async function getNip98AuthHeader (url, method, body) {
    try {
      const urlString = typeof url === 'string' ? url : url.toString();
      const bodyHash = await bodyToHashHex(body);

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

        // Request auth header (body hash only -- the raw body stays in the page)
        window.dispatchEvent(new CustomEvent('podkey-nip98-request', {
          detail: {
            id: eventId,
            url: urlString,
            method: method || 'GET',
            bodyHash
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
    if (DEBUG) console.log('[Podkey] fetch() intercepted:', urlString, method);

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
          if (DEBUG) console.log('[Podkey] Added NIP-98 auth header');
        } else if (DEBUG) {
          console.log('[Podkey] No auth header (will retry on 401)');
        }
      } catch (error) {
        console.error('[Podkey] Error adding NIP-98 auth:', error);
      }
    } else if (DEBUG) {
      console.log('[Podkey] Page already set Authorization — skipping injection');
    }

    const response = await originalFetch.call(this, url, options);

    // Handle 401 retry
    if (response.status === 401) {
      if (DEBUG) console.log('[Podkey] 401 detected, retrying with NIP-98 auth...');
      try {
        // If the original request followed a redirect, the endpoint that
        // returned 401 is response.url, not the requested url. NIP-98 binds the
        // signature to the `u` tag, so re-sign against the actual final URL.
        const retryUrl = response.redirected && response.url ? response.url : urlString;
        const authHeader = await getNip98AuthHeader(retryUrl, method, body);
        if (authHeader) {
          const retryOptions = { ...options };
          setAuthorizationOnOptions(retryOptions, authHeader);
          const retryResponse = await originalFetch.call(this, retryUrl, retryOptions);
          if (DEBUG) console.log('[Podkey] NIP-98 retry status:', retryResponse.status);
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
  XMLHttpRequest.prototype.setRequestHeader = function (name, _value) {
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
          if (DEBUG) console.log('[Podkey] Added NIP-98 auth to XHR');
        }
      } catch (error) {
        console.error('[Podkey] Error adding NIP-98 auth to XHR:', error);
      }
    } else if (this._podkeyHasPageAuth && DEBUG) {
      console.log('[Podkey] Page set XHR Authorization — skipping injection');
    }
    return originalXHRSend.apply(this, [body]);
  };

  // If the content-script bridge reports the extension context is gone (the
  // extension was reloaded/updated while this page stayed open), stop
  // intercepting and restore the native network APIs. Without this we keep
  // round-tripping a CustomEvent per request to a dead extension. A tab reload
  // re-injects a fresh interceptor bound to the live extension.
  window.addEventListener('podkey-nip98-disable', function restoreNative () {
    window.removeEventListener('podkey-nip98-disable', restoreNative);
    window.fetch = originalFetch;
    XMLHttpRequest.prototype.open = originalXHROpen;
    XMLHttpRequest.prototype.send = originalXHRSend;
    XMLHttpRequest.prototype.setRequestHeader = originalXHRSetRequestHeader;
    if (DEBUG) console.log('[Podkey] Context invalidated — native fetch/XHR restored');
  });

  if (DEBUG) console.log('[Podkey] NIP-98 interceptor injected into page context');
})();
