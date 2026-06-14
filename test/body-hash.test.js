/**
 * Tests for bodyToHashHex — the page-side NIP-98 `payload` body hashing in
 * nip98-interceptor.js. The raw request body never crosses to the background
 * service worker; the page computes its SHA-256 here (the only context where
 * FormData / URLSearchParams / Blob survive intact) and ships only the digest.
 *
 * bodyToHashHex is a private function inside the interceptor's page-context
 * IIFE (no ESM export — classic scripts can't import). To exercise the real
 * source it is loaded and run inside a vm sandbox with a minimal page (window,
 * fetch, XHR), and the bodyHash the interceptor emits on the
 * podkey-nip98-request event is captured. This drives the genuine code path
 * (window.fetch wrapper -> getNip98AuthHeader -> bodyToHashHex) rather than a
 * reimplementation.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, webcrypto } from 'node:crypto';
import vm from 'node:vm';

const sha256hex = (input) => createHash('sha256').update(input).digest('hex');

/** Build a fresh sandboxed page with the interceptor installed. */
function makeInterceptedPage () {
  const src = readFileSync(new URL('../src/nip98-interceptor.js', import.meta.url), 'utf8');
  const bus = new EventTarget();
  const win = {
    __podkey_nip98_intercepted: false,
    addEventListener: (...a) => bus.addEventListener(...a),
    removeEventListener: (...a) => bus.removeEventListener(...a),
    dispatchEvent: (e) => bus.dispatchEvent(e),
    // originalFetch: a stub the wrapper calls after deciding on auth.
    fetch: async () => ({ status: 200, redirected: false, url: '' })
  };

  // Echo every nip98 request back immediately so the fetch wrapper resolves,
  // recording the detail (which carries bodyHash) for assertions.
  const requests = [];
  bus.addEventListener('podkey-nip98-request', (e) => {
    requests.push(e.detail);
    bus.dispatchEvent(new CustomEvent('podkey-nip98-response', { detail: { id: e.detail.id, result: null } }));
  });

  // Minimal XHR so the interceptor can patch its prototype without throwing.
  function XHR () {}
  XHR.prototype = { open () {}, send () {}, setRequestHeader () {} };

  const sandbox = {
    window: win,
    XMLHttpRequest: XHR,
    crypto: webcrypto,
    CustomEvent, Headers, Request, TextEncoder,
    Blob, URLSearchParams, ArrayBuffer, Uint8Array, Uint16Array, Array, Object,
    console, setTimeout, clearTimeout
  };
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);

  return {
    /** Issue a fetch through the wrapped fetch and return the captured bodyHash. */
    async fetchAndGetHash (init) {
      requests.length = 0;
      await win.fetch('https://pod.test/r', init);
      assert.equal(requests.length, 1, 'interceptor should emit exactly one nip98 request');
      return requests[0].bodyHash;
    },
    /** Issue a fetch and return whether any nip98 request was emitted. */
    async fetchEmitsRequest (input, init) {
      requests.length = 0;
      await win.fetch(input, init);
      return requests.length > 0;
    }
  };
}

describe('bodyToHashHex (NIP-98 page-side body hashing)', () => {
  let page;
  before(() => { page = makeInterceptedPage(); });

  it('hashes a string body to its sha-256 hex', async () => {
    const body = '{"hello":"world"}';
    assert.equal(await page.fetchAndGetHash({ method: 'POST', body }), sha256hex(body));
  });

  it('hashes a URLSearchParams body via its serialized form', async () => {
    const params = new URLSearchParams({ a: '1', b: 'two' });
    assert.equal(await page.fetchAndGetHash({ method: 'POST', body: params }), sha256hex(params.toString()));
  });

  it('hashes a Blob body by its bytes', async () => {
    const text = 'blob-bytes-😀';
    const blob = new Blob([text]);
    const expected = sha256hex(Buffer.from(text, 'utf8'));
    assert.equal(await page.fetchAndGetHash({ method: 'PUT', body: blob }), expected);
  });

  it('hashes an ArrayBuffer body', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 250, 255]);
    const expected = sha256hex(Buffer.from(bytes));
    assert.equal(await page.fetchAndGetHash({ method: 'POST', body: bytes.buffer }), expected);
  });

  it('hashes a typed-array (Uint8Array) body', async () => {
    const bytes = new Uint8Array([10, 20, 30]);
    const expected = sha256hex(Buffer.from(bytes));
    assert.equal(await page.fetchAndGetHash({ method: 'POST', body: bytes }), expected);
  });

  it('respects a typed-array view offset (does not hash the whole buffer)', async () => {
    const full = new Uint8Array([0, 0, 1, 2, 3, 0]);
    const view = full.subarray(2, 5); // [1,2,3]
    const expected = sha256hex(Buffer.from([1, 2, 3]));
    assert.equal(await page.fetchAndGetHash({ method: 'POST', body: view }), expected);
  });

  it('returns "" for no body (GET)', async () => {
    assert.equal(await page.fetchAndGetHash({ method: 'GET' }), '');
  });

  it('returns "" for an empty-string body', async () => {
    assert.equal(await page.fetchAndGetHash({ method: 'POST', body: '' }), '');
  });

  it('returns "" for a FormData body (no canonical NIP-98 multipart hash)', async () => {
    // Documented decision: NIP-98 defines no canonical hash for multipart bodies,
    // so FormData is intentionally not hashed (no payload tag is added). A
    // FormData instance matches none of bodyToHashHex's recognised body types
    // (string / URLSearchParams / Blob / ArrayBuffer / typed-array) and hits the
    // `return ''` fallthrough.
    const fd = new FormData();
    fd.append('field', 'value');
    assert.equal(await page.fetchAndGetHash({ method: 'POST', body: fd }), '');
  });
});

describe('interceptor honors a page-set Authorization (no NIP-98 injection)', () => {
  let page;
  before(() => { page = makeInterceptedPage(); });

  it('does not emit a nip98 request when init.headers already has Authorization', async () => {
    const emitted = await page.fetchEmitsRequest('https://pod.test/r', {
      method: 'GET', headers: { Authorization: 'DPoP page-token' }
    });
    assert.equal(emitted, false, 'page-set DPoP must not be overwritten by NIP-98');
  });

  it('emits a nip98 request when no Authorization is present', async () => {
    const emitted = await page.fetchEmitsRequest('https://pod.test/r', { method: 'GET' });
    assert.equal(emitted, true);
  });
});
