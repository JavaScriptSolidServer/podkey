/**
 * Tests for sidestr settings (src/sidestr/settings.js): spends are off until
 * turned on, 0.0.9 pins carry over as turned on, and forgetting a chain or
 * turning spends off drops pins and cached state, chain by chain.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as settings from '../src/sidestr/settings.js';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);

/** chrome.storage.local's get/set/remove over a Map. */
function memoryStorage (initial = {}, { failSet = false } = {}) {
  const m = new Map(Object.entries(initial));
  return {
    m,
    async get (keys) {
      if (keys === null) return Object.fromEntries(m);
      const list = Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(list.filter((k) => m.has(k)).map((k) => [k, m.get(k)]));
    },
    async set (obj) { if (failSet) throw new Error('QUOTA_BYTES quota exceeded'); for (const [k, v] of Object.entries(obj)) m.set(k, v); },
    async remove (keys) { for (const k of Array.isArray(keys) ? keys : [keys]) m.delete(k); }
  };
}

describe('sidestr settings', () => {
  it('is off, with no chains, by default', async () => {
    assert.deepEqual(await settings.load(memoryStorage()), { enabled: false, chains: {} });
  });

  it('carries 0.0.9 pins over as turned on, and drops the old key on the next save', async () => {
    const st = memoryStorage({ [settings.LEGACY_PINS_KEY]: { 'sidestr:dreamlab': A, 'sidestr:bad': 'nope' } });
    const s = await settings.load(st);
    assert.equal(s.enabled, true);
    assert.deepEqual(Object.keys(s.chains), ['sidestr:dreamlab']);
    await settings.enable(st);
    assert.equal(st.m.has(settings.LEGACY_PINS_KEY), false);
    assert.equal((await settings.load(st)).chains['sidestr:dreamlab'].signer, A);
  });

  it('pins a chain once, keeping when it was first added', async () => {
    const st = memoryStorage();
    await settings.enable(st);
    await settings.pinChain(st, 'sidestr:x', A, 1000);
    await settings.pinChain(st, 'sidestr:x', A, 2000);
    assert.deepEqual((await settings.load(st)).chains['sidestr:x'], { signer: A, addedAt: 1000 });
    await assert.rejects(() => settings.pinChain(st, 'sidestr:y', 'short'));
  });

  it('forgetting a chain drops its pin and only its cache', async () => {
    const st = memoryStorage();
    await settings.enable(st);
    await settings.pinChain(st, 'sidestr:lab', A);
    await settings.pinChain(st, 'sidestr:dreamlab', B);
    const cache = settings.cacheStore(st);
    await cache.set('sidestr:state:sidestr:lab', '1');
    await cache.set('assets:sidestr:lab', '2');
    await cache.set('sidestr:state:sidestr:dreamlab', '3');
    await settings.forgetChain(st, 'sidestr:lab');
    const s = await settings.load(st);
    assert.deepEqual(Object.keys(s.chains), ['sidestr:dreamlab']);
    assert.equal(await cache.get('assets:sidestr:lab'), null);
    assert.equal(await cache.get('sidestr:state:sidestr:lab'), null);
    assert.equal(await cache.get('sidestr:state:sidestr:dreamlab'), '3', 'a chain whose id ends the same is untouched');
  });

  it('turning spends off forgets every chain and every cache', async () => {
    const st = memoryStorage();
    await settings.enable(st);
    await settings.pinChain(st, 'sidestr:x', A);
    await settings.cacheStore(st).set('assets:sidestr:x', 'v');
    st.m.set('podkey_trusted_origins', { 'https://a.example': true });
    await settings.disable(st);
    assert.deepEqual(await settings.load(st), { enabled: false, chains: {} });
    assert.deepEqual([...st.m.keys()].filter((k) => k.startsWith(settings.CACHE_PREFIX)), []);
    assert.ok(st.m.has('podkey_trusted_origins'), 'other settings are untouched');
  });

  it('the cache store namespaces keys, and a failed write is not an error', async () => {
    const st = memoryStorage();
    const cache = settings.cacheStore(st);
    await cache.set('k', 'v');
    assert.ok(st.m.has(settings.CACHE_PREFIX + 'k'));
    assert.equal(await cache.get('k'), 'v');
    await cache.delete('k');
    assert.equal(await cache.get('k'), null);
    await settings.cacheStore(memoryStorage({}, { failSet: true })).set('k', 'v');
  });
});
