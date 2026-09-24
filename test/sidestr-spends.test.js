/**
 * Tests for the background's side of a sidestr spend (src/sidestr/spends.js):
 * the request opens the window, the window signs once, the outcome resolves
 * the page's promise, and closing, silence or a locked key reject it.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSpends, SPEND_WINDOW_MS } from '../src/sidestr/spends.js';

const PUB = 'a'.repeat(64);
const REQ = { chain: 'sidestr:dreamlab', tx: '0200' };

function harness ({ locked = false, key = { publicKey: PUB, privateKey: 'b'.repeat(64) } } = {}) {
  const timers = []; const opened = []; let n = 0;
  const signed = [];
  const spends = createSpends({
    ensureUnlocked: async () => { if (locked) throw new Error('Podkey is locked'); },
    getKeypair: async () => key,
    signSighashes: (digests, priv) => { signed.push({ digests, priv }); return digests.map(() => 'c'.repeat(128)); },
    openWindow: async (id) => { opened.push(id); return 42; },
    setTimer: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearTimer: () => {},
    randomId: () => `id-${++n}`
  });
  const tick = () => new Promise((resolve) => setImmediate(resolve));
  return { spends, timers, opened, signed, tick };
}

describe('sidestr spends', () => {
  it('opens the window and resolves with the signed transaction after one signing', async () => {
    const h = harness();
    const p = h.spends.request(REQ, 'https://forum.example');
    await h.tick();
    assert.deepEqual(h.opened, ['id-1']);
    const d = h.spends.describe('id-1');
    assert.equal(d.origin, 'https://forum.example');
    assert.equal(d.pub, PUB);
    assert.ok(d.expiresAt > Date.now() && d.expiresAt <= Date.now() + SPEND_WINDOW_MS);
    const { signatures } = await h.spends.signDigests('id-1', ['d'.repeat(64)]);
    assert.equal(signatures.length, 1);
    await assert.rejects(() => h.spends.signDigests('id-1', ['d'.repeat(64)]), /already been signed/);
    h.spends.done('id-1', { result: { tx: 'ff', txid: 'e'.repeat(64) } });
    assert.deepEqual(await p, { tx: 'ff', txid: 'e'.repeat(64) });
    assert.equal(h.spends.pending.size, 0);
  });

  it('refuses a result for a spend that was never signed', async () => {
    const h = harness();
    const p = h.spends.request(REQ, 'https://x.example');
    await h.tick();
    h.spends.done('id-1', { result: { tx: 'ff', txid: 'e'.repeat(64) } });
    await assert.rejects(p, (e) => e.code === 'unavailable');
  });

  it('a rejection in the window reaches the page with its code', async () => {
    const h = harness();
    const p = h.spends.request(REQ, 'https://x.example');
    await h.tick();
    h.spends.done('id-1', { error: { code: 'rejected', message: 'You rejected the spend' } });
    await assert.rejects(p, (e) => e.code === 'rejected' && /rejected the spend/.test(e.message));
  });

  it('closing the window rejects', async () => {
    const h = harness();
    const p = h.spends.request(REQ, 'https://x.example');
    await h.tick();
    h.spends.windowClosed(7); // another window: nothing happens
    assert.equal(h.spends.pending.size, 1);
    h.spends.windowClosed(42);
    await assert.rejects(p, (e) => e.code === 'rejected');
  });

  it('silence rejects when the timer fires', async () => {
    const h = harness();
    const p = h.spends.request(REQ, 'https://x.example');
    await h.tick();
    assert.ok(h.timers[0].ms > SPEND_WINDOW_MS);
    h.timers[0].fn();
    await assert.rejects(p, (e) => e.code === 'rejected' && /timed out/.test(e.message));
  });

  it('checks the request before opening anything', async () => {
    const h = harness();
    await assert.rejects(() => h.spends.request({ chain: 'nope', tx: '00' }, 'https://x.example'), (e) => e.code === 'invalid');
    await assert.rejects(() => h.spends.request(REQ, ''), (e) => e.code === 'invalid');
    assert.equal(h.opened.length, 0);
  });

  it('a locked key is unavailable, and no window opens', async () => {
    const h = harness({ locked: true });
    await assert.rejects(() => h.spends.request(REQ, 'https://x.example'), (e) => e.code === 'unavailable');
    assert.equal(h.opened.length, 0);
  });

  it('refuses to sign if the key changed while the window was open', async () => {
    const h = harness();
    const p = h.spends.request(REQ, 'https://x.example');
    await h.tick();
    h.spends.pending.get('id-1').pub = 'f'.repeat(64);
    await assert.rejects(() => h.spends.signDigests('id-1', ['d'.repeat(64)]), /key changed/);
    assert.equal(h.signed.length, 0);
    h.spends.windowClosed(42);
    await assert.rejects(p);
  });

  it('refuses an empty or oversized digest list', async () => {
    const h = harness();
    const p = h.spends.request(REQ, 'https://x.example');
    await h.tick();
    await assert.rejects(() => h.spends.signDigests('id-1', []), (e) => e.code === 'invalid');
    h.spends.windowClosed(42);
    await assert.rejects(p);
  });
});
