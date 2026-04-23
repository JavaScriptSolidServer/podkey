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
  const originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

  // Duplicate of src/auth-header-utils.js — keep in sync. The canonical
  // module is imported by unit tests; this copy runs in content-script
  // context where classic scripts can't use ESM imports. Build-time
  // bundling to drop the duplication is tracked in #7.
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

  // Helper to get auth header (will be async, but we'll handle that)
  let getAuthHeaderFn = null;

  // Set up the async auth header function (will be defined below)
  function setAuthHeaderFn (fn) {
    getAuthHeaderFn = fn;
  }

  // Intercept fetch - MUST replace immediately to catch all calls
  // This runs synchronously, so it catches fetch even if called immediately
  window.fetch = function (url, options = {}) {
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
    // own auth. If it fails with 401, the retry path below still injects
    // NIP-98. See issue #5.
    const pageSetAuth = fetchCallHasAuthorization(url, options);

    // If we have the auth function, use it
    if (getAuthHeaderFn && !pageSetAuth) {
      console.log('[Podkey] ✅ Auth function ready, adding header...');
      const promise = (async () => {
        try {
          const authHeader = await getAuthHeaderFn(urlString, method, body);
          if (authHeader) {
            setAuthorizationOnOptions(options, authHeader);
            console.log('[Podkey] ✅ Added NIP-98 auth header');
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
              const authHeader = await getAuthHeaderFn(urlString, method, body);
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
            } catch (e) {
              console.error('[Podkey] Error in 401 retry:', e);
            }
            return response;
          })();
        }
        return response;
      });
    }

    // Fall-through branch: we're here because either the page set its own
    // Authorization (and we deliberately skipped initial injection) or the
    // auth function isn't wired up yet. Send the request as-is; on 401,
    // retry with NIP-98 — either immediately if ready, or after waiting
    // for setup (with a hard deadline so we don't hang forever).
    if (pageSetAuth) {
      console.log('[Podkey] ⏭️ Page already set Authorization — skipping initial injection');
    } else {
      console.log('[Podkey] ⚠️ Auth function not ready yet, making request...');
    }

    const requestPromise = originalFetch.call(this, url, options);

    const AUTH_READY_DEADLINE_MS = 5000;

    // If we get a 401 and auth becomes available, retry
    return requestPromise.then(response => {
      if (response.status === 401) {
        console.log('[Podkey] 🔄 Got 401, checking if auth function is ready now...');
        // Wait for auth function to be ready, bounded by deadline. Every
        // async step below has an error handler so the outer promise is
        // guaranteed to settle (otherwise the caller would hang).
        return new Promise((resolve) => {
          const deadline = Date.now() + AUTH_READY_DEADLINE_MS;
          const checkAuth = () => {
            if (getAuthHeaderFn) {
              console.log('[Podkey] 🔄 Auth function now ready, retrying with NIP-98...');
              getAuthHeaderFn(urlString, method, body)
                .then(authHeader => {
                  if (authHeader) {
                    const retryOptions = { ...options };
                    setAuthorizationOnOptions(retryOptions, authHeader);
                    originalFetch.call(this, url, retryOptions)
                      .then(resolve)
                      .catch(err => {
                        console.error('[Podkey] Retry fetch failed:', err);
                        resolve(response);
                      });
                  } else {
                    resolve(response);
                  }
                })
                .catch(err => {
                  console.error('[Podkey] Error getting auth header for retry:', err);
                  resolve(response);
                });
            } else if (Date.now() >= deadline) {
              console.log('[Podkey] ⚠️ Auth function still not ready after deadline, giving up');
              resolve(response);
            } else {
              // Check again in 100ms
              setTimeout(checkAuth, 100);
            }
          };
          checkAuth();
        });
      }
      return response;
    });
  };

  // Intercept XMLHttpRequest
  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    this._podkeyMethod = method;
    this._podkeyUrl = url;
    this._podkeyHasPageAuth = false;
    return originalXHROpen.apply(this, [method, url, ...args]);
  };

  // Track a page-set Authorization on XHR so send() can respect it.
  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    if (typeof name === 'string' && name.toLowerCase() === 'authorization') {
      this._podkeyHasPageAuth = true;
    }
    return originalXHRSetRequestHeader.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    // setRequestHeader must run before send(); defer originalXHRSend until
    // the header is applied (or skipped), else the async setRequestHeader
    // would fire after the request is already in-flight and throw
    // InvalidStateError.
    const runSend = () => originalXHRSend.apply(this, [body]);
    if (getAuthHeaderFn && this._podkeyUrl && !this._podkeyHasPageAuth) {
      getAuthHeaderFn(this._podkeyUrl, this._podkeyMethod, body)
        .then(authHeader => {
          if (authHeader) {
            originalXHRSetRequestHeader.call(this, 'Authorization', authHeader);
          }
        })
        .catch(e => {
          console.error('[Podkey] Error in XHR interceptor:', e);
        })
        .finally(runSend);
    } else {
      runSend();
    }
  };

  // Expose setter for the auth function
  window.__podkey_setAuthFn = setAuthHeaderFn;

  console.log('[Podkey] ✅ Synchronous interception setup complete');
})();

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

// Listen for NIP-98 auth requests from page context
window.addEventListener('podkey-nip98-request', async (event) => {
  const { id, url, method, body } = event.detail;

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'CREATE_NIP98_AUTH_HEADER',
      url,
      method,
      body
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
