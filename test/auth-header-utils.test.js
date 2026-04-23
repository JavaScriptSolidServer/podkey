import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  hasAuthorizationHeader,
  fetchCallHasAuthorization,
  setAuthorizationOnOptions,
  normalizeFetchCall
} from '../src/auth-header-utils.js';

describe('hasAuthorizationHeader (#5)', () => {
  it('returns false for undefined / empty', () => {
    assert.strictEqual(hasAuthorizationHeader(undefined), false);
    assert.strictEqual(hasAuthorizationHeader(null), false);
    assert.strictEqual(hasAuthorizationHeader({}), false);
  });

  it('detects plain-object Authorization (exact case)', () => {
    assert.strictEqual(hasAuthorizationHeader({ Authorization: 'DPoP xxx' }), true);
  });

  it('detects plain-object authorization case-insensitively', () => {
    assert.strictEqual(hasAuthorizationHeader({ authorization: 'DPoP xxx' }), true);
    assert.strictEqual(hasAuthorizationHeader({ AUTHORIZATION: 'DPoP xxx' }), true);
    assert.strictEqual(hasAuthorizationHeader({ aUtHoRiZaTiOn: 'DPoP xxx' }), true);
  });

  it('returns false when plain object has unrelated headers', () => {
    assert.strictEqual(
      hasAuthorizationHeader({ 'Content-Type': 'application/json', 'X-Foo': 'bar' }),
      false
    );
  });

  it('detects Headers instance (case-insensitive per spec)', () => {
    const h = new Headers();
    h.set('Authorization', 'DPoP xxx');
    assert.strictEqual(hasAuthorizationHeader(h), true);
    assert.strictEqual(hasAuthorizationHeader(new Headers()), false);
  });

  it('detects array-of-tuples shape', () => {
    assert.strictEqual(
      hasAuthorizationHeader([['Content-Type', 'application/json'], ['authorization', 'Bearer x']]),
      true
    );
    assert.strictEqual(
      hasAuthorizationHeader([['Content-Type', 'application/json']]),
      false
    );
  });

  it('does not false-positive on header names that merely contain "authorization"', () => {
    assert.strictEqual(
      hasAuthorizationHeader({ 'X-Authorization-Source': 'podkey' }),
      false
    );
  });
});

describe('fetchCallHasAuthorization (#5)', () => {
  it('returns false for fetch(url) with no init', () => {
    assert.strictEqual(fetchCallHasAuthorization('https://x.test/', undefined), false);
  });

  it('returns true when init.headers carries Authorization', () => {
    assert.strictEqual(
      fetchCallHasAuthorization('https://x.test/', { headers: { Authorization: 'DPoP x' } }),
      true
    );
  });

  it('returns true when a Request input carries Authorization (no init override)', () => {
    const req = new Request('https://x.test/', {
      headers: { Authorization: 'DPoP x' }
    });
    assert.strictEqual(fetchCallHasAuthorization(req, undefined), true);
  });

  it('returns false for a Request input without Authorization', () => {
    const req = new Request('https://x.test/');
    assert.strictEqual(fetchCallHasAuthorization(req, undefined), false);
  });

  it('init.headers overrides Request.headers (no false positive from Request)', () => {
    // Per fetch spec, init.headers completely replaces Request.headers.
    // If Request had auth but init supplies its own (non-auth) headers,
    // the effective request has NO auth and we must NOT skip injection.
    const req = new Request('https://x.test/', {
      headers: { Authorization: 'DPoP old' }
    });
    assert.strictEqual(
      fetchCallHasAuthorization(req, { headers: { 'Content-Type': 'application/json' } }),
      false
    );
  });

  it('init.headers with Authorization is detected even when Request has none', () => {
    const req = new Request('https://x.test/');
    assert.strictEqual(
      fetchCallHasAuthorization(req, { headers: { Authorization: 'DPoP new' } }),
      true
    );
  });
});

describe('setAuthorizationOnOptions (#5)', () => {
  it('sets on a plain object', () => {
    const options = { headers: { 'Content-Type': 'application/json' } };
    setAuthorizationOnOptions(options, 'Nostr xyz');
    assert.strictEqual(options.headers['Authorization'], 'Nostr xyz');
  });

  it('creates headers object when missing', () => {
    const options = {};
    setAuthorizationOnOptions(options, 'Nostr xyz');
    assert.strictEqual(options.headers['Authorization'], 'Nostr xyz');
  });

  it('sets on a Headers instance via .set', () => {
    const options = { headers: new Headers({ 'Content-Type': 'application/json' }) };
    setAuthorizationOnOptions(options, 'Nostr xyz');
    assert.strictEqual(options.headers.get('authorization'), 'Nostr xyz');
  });

  it('replaces an existing Authorization across casings (no comma-merge)', () => {
    // 401-retry path intentionally overwrites; the old lowercase key must be
    // removed so fetch doesn't end up merging "DPoP …, Nostr …".
    const options = { headers: { authorization: 'DPoP original', 'Content-Type': 'application/json' } };
    setAuthorizationOnOptions(options, 'Nostr replacement');
    const authKeys = Object.keys(options.headers).filter((k) => k.toLowerCase() === 'authorization');
    assert.strictEqual(authKeys.length, 1, `expected exactly one auth key, got: ${authKeys.join(',')}`);
    assert.strictEqual(options.headers[authKeys[0]], 'Nostr replacement');
  });

  it('normalizes array-of-tuples to Headers and sets there', () => {
    // A raw array would silently swallow `options.headers['Authorization'] = x`;
    // normalization is what actually makes the injection take effect.
    const options = { headers: [['Content-Type', 'application/json']] };
    setAuthorizationOnOptions(options, 'Nostr xyz');
    assert.ok(options.headers instanceof Headers, 'headers should be normalized to Headers');
    assert.strictEqual(options.headers.get('authorization'), 'Nostr xyz');
    // Original header preserved through the normalization.
    assert.strictEqual(options.headers.get('content-type'), 'application/json');
  });
});

describe('normalizeFetchCall (#5)', () => {
  it('extracts url/method from a string input and init', () => {
    const n = normalizeFetchCall('https://x.test/a', { method: 'PUT', body: 'hello' });
    assert.strictEqual(n.url, 'https://x.test/a');
    assert.strictEqual(n.method, 'PUT');
    assert.strictEqual(n.body, 'hello');
  });

  it('defaults method to GET when init omits it', () => {
    const n = normalizeFetchCall('https://x.test/', undefined);
    assert.strictEqual(n.method, 'GET');
  });

  it('extracts url/method from a Request input (not "[object Request]")', () => {
    const req = new Request('https://x.test/b', { method: 'POST' });
    const n = normalizeFetchCall(req, undefined);
    assert.strictEqual(n.url, 'https://x.test/b');
    assert.strictEqual(n.method, 'POST');
  });

  it('init method overrides Request method when both present (per fetch spec)', () => {
    const req = new Request('https://x.test/b', { method: 'POST' });
    const n = normalizeFetchCall(req, { method: 'PUT' });
    assert.strictEqual(n.method, 'PUT');
  });
});
