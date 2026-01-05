# Implement Automatic NIP-98 HTTP Authentication

## Overview

Currently, Podkey provides NIP-07 `window.nostr` API for websites to manually create and sign NIP-98 auth events, but it does **not automatically intercept HTTP requests** to add NIP-98 Authorization headers. This issue tracks the implementation of automatic NIP-98 authentication for Solid servers and other Nostr-authenticated HTTP endpoints.

## Current State

- ✅ Extension has `webRequest` permission in `manifest.json`
- ✅ Extension can sign NIP-98 events (kind 27235) via `window.nostr.signEvent()`
- ✅ Auto-sign functionality exists for trusted origins
- ❌ **No automatic HTTP request interception**
- ❌ **No automatic 401 response detection and retry**
- ❌ **No automatic Authorization header injection**

## NIP-98 Specification Reference

**Specification:** https://github.com/nostr-protocol/nips/blob/master/98.md

### Event Structure

```json
{
  "kind": 27235,
  "content": "",
  "tags": [
    ["u", "https://example.com/api/resource?query=value"],
    ["method", "GET"]
  ],
  "created_at": 1682327852
}
```

### Authorization Header Format

```
Authorization: Nostr <base64-encoded-signed-event>
```

### For Requests with Body (POST, PUT, etc.)

Include a `payload` tag with SHA-256 hash of the request body:
```json
{
  "tags": [
    ["u", "https://example.com/api/resource"],
    ["method", "POST"],
    ["payload", "<sha256-hex-of-body>"]
  ]
}
```

## Implementation Requirements

### 1. HTTP Request Interception

**Location:** `src/background.js`

**Implementation:**
- Use `chrome.webRequest.onBeforeSendHeaders` to intercept outgoing requests
- Filter requests to origins that:
  - Are trusted (via `isTrustedOrigin()`)
  - Have auto-sign enabled (via `getAutoSign()`)
  - OR are Solid servers (detect via domain patterns or explicit list)

**Considerations:**
- Only intercept requests to origins that have been trusted or are known Solid servers
- Don't intercept requests that already have an `Authorization` header (unless it's a retry)
- Cache signed auth events per request URL+method to avoid re-signing identical requests

### 2. 401 Response Detection and Retry

**Location:** `src/background.js`

**Implementation:**
- Use `chrome.webRequest.onHeadersReceived` to detect 401 responses
- When 401 is detected:
  1. Check if origin is trusted
  2. Create NIP-98 auth event for the failed request
  3. Sign the event using existing `signEvent()` function
  4. Retry the original request with `Authorization: Nostr <base64-event>` header

**Retry Logic:**
- Only retry on **401 Unauthorized** responses
- Consider **403 Forbidden** if it's auth-related (optional, may need user preference)
- **Do NOT retry** on other 4xx errors (404, 400, etc.) - these are not auth issues
- Limit retry attempts (max 1 retry per request to avoid loops)
- Track retry state to prevent infinite loops

### 3. NIP-98 Event Creation

**Location:** `src/background.js` (new function)

**Function Signature:**
```javascript
async function createNip98AuthEvent(requestDetails) {
  // requestDetails from chrome.webRequest API
  // Returns: unsigned event object ready for signing
}
```

**Event Creation:**
```javascript
const event = {
  kind: 27235,
  content: "",
  created_at: Math.floor(Date.now() / 1000),
  tags: [
    ["u", requestDetails.url],  // Full URL including query params
    ["method", requestDetails.method]
  ]
};

// If request has body, add payload tag
if (requestDetails.requestBody) {
  const bodyHash = await hashRequestBody(requestDetails.requestBody);
  event.tags.push(["payload", bodyHash]);
}
```

### 4. Request Body Hashing

**Location:** `src/background.js` or `src/crypto.js`

**Implementation:**
- For requests with body (POST, PUT, PATCH), compute SHA-256 hash
- Use existing `@noble/hashes` library (already in dependencies)
- Handle different body formats:
  - `FormData` → convert to bytes
  - `ArrayBuffer` → use directly
  - `Blob` → read as ArrayBuffer
  - `string` → encode to UTF-8 bytes

### 5. Base64 Encoding

**Location:** `src/background.js` or utility function

**Implementation:**
- Encode signed event JSON to base64
- Use browser's built-in `btoa()` or `Buffer` (Node.js style)
- Format: `Authorization: Nostr <base64-string>`

### 6. User Preferences

**Location:** `src/storage.js` (may need additions)

**Considerations:**
- Add setting: "Auto-authenticate HTTP requests" (separate from event auto-sign)
- Add setting: "Retry on 403 Forbidden" (optional, default false)
- Add setting: "Solid server domains" (whitelist for auto-auth)
- Respect existing `getAutoSign()` preference

## Code Structure

### New Functions Needed

```javascript
// In src/background.js

/**
 * Create NIP-98 authentication event for an HTTP request
 */
async function createNip98AuthEvent(requestDetails) {
  // Implementation
}

/**
 * Hash request body for NIP-98 payload tag
 */
async function hashRequestBody(requestBody) {
  // Implementation using @noble/hashes
}

/**
 * Encode signed event to Authorization header value
 */
function encodeNip98Header(signedEvent) {
  // Implementation
}

/**
 * Handle 401 response - create auth and retry
 */
async function handle401Response(details) {
  // Implementation
}

/**
 * Intercept requests and add NIP-98 auth if needed
 */
function interceptRequest(details) {
  // Implementation
}
```

### WebRequest Listeners

```javascript
// In src/background.js initialization

// Intercept outgoing requests
chrome.webRequest.onBeforeSendHeaders.addListener(
  interceptRequest,
  {
    urls: ["<all_urls>"],
    types: ["xmlhttprequest", "main_frame", "sub_frame"]
  },
  ["requestHeaders", "blocking"]
);

// Detect 401 responses
chrome.webRequest.onHeadersReceived.addListener(
  handle401Response,
  {
    urls: ["<all_urls>"],
    types: ["xmlhttprequest", "main_frame", "sub_frame"]
  },
  ["responseHeaders"]
);
```

## Edge Cases and Considerations

1. **Request Body Handling:**
   - Different formats (FormData, Blob, ArrayBuffer, string)
   - Large bodies (consider streaming or size limits)
   - Binary data encoding

2. **URL Normalization:**
   - Ensure `u` tag matches exactly what server expects
   - Include query parameters
   - Handle URL encoding/decoding

3. **Timing:**
   - `created_at` should be recent (within 60 seconds typically)
   - Consider request timing vs. event creation timing

4. **Caching:**
   - Cache signed events per (URL, method, bodyHash) tuple
   - Invalidate cache after expiration (e.g., 60 seconds)
   - Avoid re-signing identical requests

5. **Security:**
   - Only auto-auth for trusted origins
   - Respect user's auto-sign preference
   - Don't leak private keys or expose auth events unnecessarily

6. **Performance:**
   - Minimize blocking operations
   - Use async/await properly
   - Consider request queuing for retries

7. **Error Handling:**
   - Handle signing failures gracefully
   - Log errors for debugging
   - Don't break normal browsing if auth fails

## Testing Requirements

1. **Unit Tests:**
   - `createNip98AuthEvent()` with various request types
   - `hashRequestBody()` with different body formats
   - `encodeNip98Header()` encoding correctness

2. **Integration Tests:**
   - Mock Solid server that requires NIP-98 auth
   - Test 401 detection and retry flow
   - Test auto-auth for trusted origins
   - Test that non-trusted origins don't get auto-auth

3. **Manual Testing:**
   - Test with real Solid server
   - Test with various HTTP methods (GET, POST, PUT, DELETE)
   - Test with and without request bodies
   - Test retry behavior on 401
   - Verify no retry on other 4xx errors

## Acceptance Criteria

- [ ] Extension automatically adds NIP-98 Authorization header to requests from trusted origins
- [ ] Extension detects 401 responses and retries with NIP-98 auth
- [ ] NIP-98 events are correctly formatted per specification
- [ ] Request bodies are hashed and included in `payload` tag when present
- [ ] Only 401 (and optionally 403) responses trigger retry
- [ ] User preferences (auto-sign, trusted origins) are respected
- [ ] No infinite retry loops
- [ ] Works with GET, POST, PUT, DELETE, PATCH methods
- [ ] Handles various request body formats correctly
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing with real Solid server succeeds

## Related Files

- `src/background.js` - Main implementation location
- `src/crypto.js` - May need body hashing utilities
- `src/storage.js` - User preferences storage
- `manifest.json` - Already has `webRequest` permission ✅

## References

- [NIP-98 Specification](https://github.com/nostr-protocol/nips/blob/master/98.md)
- [Chrome WebRequest API](https://developer.chrome.com/docs/extensions/reference/webRequest/)
- [Solid Project Authentication](https://solidproject.org/TR/oidc)

## Notes

- This feature should be opt-in via user preferences
- Consider adding UI in popup to enable/disable auto-auth
- May want to show notification when auto-auth succeeds/fails
- Consider rate limiting to prevent abuse
