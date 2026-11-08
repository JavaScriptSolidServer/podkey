/**
 * Tests for the unsigned retry (#33). A NIP-98 Authorization header turns a
 * cross-origin GET into a non-simple request, so the browser sends a CORS
 * preflight first. Hosts that don't answer preflights (GitHub Pages) make the
 * fetch reject with a TypeError, and a public file breaks only because the
 * user is logged in. The interceptor now tries once more without its header.
 *
 * The helpers are tested from src/auth-header-utils.js, and the real
 * interceptor is run in a vm sandbox (as in body-hash.test.js) with a fake
 * fetch that fails whenever Authorization is present, like a host with no
 * preflight support.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import vm from 'node:vm';
import { shouldRetryUnsigned, withoutAuthorization } from '../src/auth-header-utils.js';

const corsError = () => new TypeError('Failed to fetch');

describe('shouldRetryUnsigned (#33)', () => {
  it('retries a signed GET or HEAD that failed with a TypeError', () => {
    assert.equal(shouldRetryUnsigned({ method: 'GET', signed: true, error: corsError() }), true);
    assert.equal(shouldRetryUnsigned({ method: 'head', signed: true, error: corsError() }), true);
    assert.equal(shouldRetryUnsigned({ method: undefined, signed: true, error: corsError() }), true);
  });

  it('never retries when Podkey did not sign (page auth, or no key)', () => {
    assert.equal(shouldRetryUnsigned({ method: 'GET', signed: false, error: corsError() }), false);
  });

  it('never retries writes', () => {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      assert.equal(shouldRetryUnsigned({ method, signed: true, error: corsError() }), false, method);
    }
  });

  it('never retries aborts', () => {
    const ac = new AbortController();
    ac.abort();
    assert.equal(shouldRetryUnsigned({ method: 'GET', signed: true, error: corsError(), signal: ac.signal }), false);
    const abort = new DOMException('aborted', 'AbortError');
    assert.equal(shouldRetryUnsigned({ method: 'GET', signed: true, error: abort }), false);
  });

  it('matches TypeError by name, so it works across realms', () => {
    const foreign = vm.runInNewContext('new TypeError("Failed to fetch")');
    assert.equal(foreign instanceof TypeError, false);
    assert.equal(shouldRetryUnsigned({ method: 'GET', signed: true, error: foreign }), true);
  });
});

describe('withoutAuthorization (#33)', () => {
  it('drops headers entirely when the caller passed none', () => {
    const init = { method: 'GET', headers: { Authorization: 'Nostr x' } };
    const out = withoutAuthorization(init, false);
    assert.equal(Object.prototype.hasOwnProperty.call(out, 'headers'), false);
    assert.equal(out.method, 'GET');
  });

  it('removes Authorization from a plain object, keeping the rest', () => {
    const init = { headers: { Accept: 'application/json', authorization: 'Nostr x' } };
    const out = withoutAuthorization(init, true);
    assert.deepEqual(out.headers, { Accept: 'application/json' });
    assert.equal(init.headers.authorization, 'Nostr x', 'must not mutate the original');
  });

  it('removes Authorization from Headers and from tuple arrays', () => {
    const h = new Headers({ Accept: 'text/html', Authorization: 'Nostr x' });
    const out = withoutAuthorization({ headers: h }, true);
    assert.equal(out.headers.has('authorization'), false);
    assert.equal(out.headers.get('accept'), 'text/html');
    assert.equal(h.has('authorization'), true, 'must not mutate the original');

    const arr = withoutAuthorization({ headers: [['Accept', 'a'], ['Authorization', 'Nostr x']] }, true);
    assert.deepEqual(arr.headers, [['Accept', 'a']]);
  });
});

/** The real interceptor in a sandbox whose network rejects any request carrying Authorization. */
function makePage ({ token = 'Nostr signed' } = {}) {
  const src = readFileSync(new URL('../src/nip98-interceptor.js', import.meta.url), 'utf8');
  const bus = new EventTarget();
  const calls = [];
  const auth = init => {
    const h = init && init.headers;
    if (!h) return null;
    if (h instanceof Headers) return h.get('authorization');
    if (Array.isArray(h)) return (h.find(e => e[0].toLowerCase() === 'authorization') || [])[1] || null;
    const key = Object.keys(h).find(k => k.toLowerCase() === 'authorization');
    return key ? h[key] : null;
  };
  const win = {
    __podkey_nip98_intercepted: false,
    addEventListener: (...a) => bus.addEventListener(...a),
    removeEventListener: (...a) => bus.removeEventListener(...a),
    dispatchEvent: (e) => bus.dispatchEvent(e),
    // a static host with no preflight support: Authorization makes the fetch fail
    fetch: async (url, init) => {
      calls.push({ url, auth: auth(init), hasHeadersKey: !!init && Object.prototype.hasOwnProperty.call(init, 'headers') });
      if (auth(init)) throw new TypeError('Failed to fetch');
      return { status: 200, redirected: false, url: String(url) };
    }
  };
  // the extension signs every request for this trusted origin
  bus.addEventListener('podkey-nip98-request', (e) => {
    bus.dispatchEvent(new CustomEvent('podkey-nip98-response', { detail: { id: e.detail.id, result: token } }));
  });
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
  return { fetch: (...a) => win.fetch(...a), calls };
}

describe('interceptor: unsigned retry when a signed fetch fails (#33)', () => {
  it('a public GET still loads: signed attempt fails, unsigned retry succeeds', async () => {
    const page = makePage();
    const res = await page.fetch('https://user.github.io/maps/sugar.json');
    assert.equal(res.status, 200);
    assert.equal(page.calls.length, 2);
    assert.equal(page.calls[0].auth, 'Nostr signed');
    assert.equal(page.calls[1].auth, null);
    assert.equal(page.calls[1].hasHeadersKey, false, 'no headers key, so a Request keeps its own headers');
  });

  it('keeps the page\'s other headers on the retry', async () => {
    const page = makePage();
    await page.fetch('https://user.github.io/a.json', { headers: { Accept: 'application/json' } });
    assert.equal(page.calls.length, 2);
    assert.equal(page.calls[1].auth, null);
  });

  it('does not retry a POST: the error reaches the page', async () => {
    const page = makePage();
    await assert.rejects(page.fetch('https://user.github.io/a.json', { method: 'POST', body: 'x' }), { name: 'TypeError' });
    assert.equal(page.calls.length, 1);
  });

  it('does not retry when the page set its own Authorization', async () => {
    const page = makePage();
    await assert.rejects(page.fetch('https://user.github.io/a.json', { headers: { Authorization: 'DPoP page' } }), { name: 'TypeError' });
    assert.equal(page.calls.length, 1);
  });

  it('does not retry when Podkey did not sign', async () => {
    const page = makePage({ token: null });
    const res = await page.fetch('https://user.github.io/a.json');
    assert.equal(res.status, 200);
    assert.equal(page.calls.length, 1);
  });
});
