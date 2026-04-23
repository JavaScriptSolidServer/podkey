/**
 * Utility: detect whether a fetch-options / headers shape already carries
 * an Authorization header. Podkey's interceptors must not overwrite an
 * Authorization header the page already set (e.g., Solid-OIDC DPoP),
 * otherwise the request ends up authenticated as Podkey's NIP-98 identity
 * and ACLs reject the real user (see issue #5).
 *
 * Handles all three shapes `options.headers` can take per the fetch spec:
 *   - `Headers` instance
 *   - plain object { 'Authorization': '...' }
 *   - array of [name, value] tuples
 */
export function hasAuthorizationHeader (headers) {
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

/**
 * Detect whether a `fetch(input, init)` call already carries an Authorization
 * header anywhere — either on `init.headers` or on the input when it is a
 * `Request` object.
 *
 * Per the fetch spec, when `input` is a `Request` and `init.headers` is
 * supplied, `init.headers` overrides the Request's headers entirely.
 * Therefore `init.headers` is authoritative when present, and
 * `input.headers` is only consulted when `init.headers` is absent.
 */
export function fetchCallHasAuthorization (input, init) {
  if (init && Object.prototype.hasOwnProperty.call(init, 'headers')) {
    return hasAuthorizationHeader(init.headers);
  }
  if (typeof Request !== 'undefined' && input instanceof Request) {
    return hasAuthorizationHeader(input.headers);
  }
  return false;
}

/**
 * Extract `{ url, method, body }` from a `fetch(input, init)` call so
 * downstream signers (NIP-98) see the actual URL/method regardless of
 * whether the caller used `fetch(url, init)` or `fetch(new Request(...))`.
 *
 * Per the fetch spec, when input is a Request and init supplies a method,
 * init's method wins. Body is read from init when provided; we do not read
 * from Request.body here because that consumes the stream — callers that
 * need body-hashing for Request inputs should clone before signing.
 */
export function normalizeFetchCall (input, init) {
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

/**
 * Set an Authorization header on `options.headers`, normalizing any of the
 * three supported shapes so the assignment actually takes effect:
 *   - `Headers` instance → `.set('Authorization', value)`
 *   - plain object       → `headers.Authorization = value`
 *   - array of tuples    → normalized to `Headers` (so the array shape
 *                          doesn't silently swallow the injection)
 * Mutates `options` in place and returns the updated headers for clarity.
 */
export function setAuthorizationOnOptions (options, value) {
  options.headers = options.headers || {};
  if (typeof Headers !== 'undefined' && options.headers instanceof Headers) {
    options.headers.set('Authorization', value);
  } else if (Array.isArray(options.headers)) {
    // Assigning an 'Authorization' property to an array would not add a
    // header, so normalize to `Headers` first.
    const normalized = new Headers(options.headers);
    normalized.set('Authorization', value);
    options.headers = normalized;
  } else {
    // Delete any existing case-insensitive match before setting the new
    // value; otherwise fetch may see both keys and merge them into a
    // "DPoP …, Nostr …" comma-joined header.
    for (const key of Object.keys(options.headers)) {
      if (key.toLowerCase() === 'authorization') delete options.headers[key];
    }
    options.headers['Authorization'] = value;
  }
  return options.headers;
}
