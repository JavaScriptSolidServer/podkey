/**
 * Tests for the NIP-07 provider surface (nostr-provider.js).
 *
 * The provider must advertise ONLY what it implements, so that page-side
 * feature-detection is truthful:
 *   - exposes getPublicKey, signEvent, nip44.{encrypt,decrypt}
 *   - does NOT expose nip04 (deprecated, unauthenticated; not shipped)
 *   - does NOT expose getRelays (Podkey holds no relay list)
 *
 * nostr-provider.js is a page-context IIFE that assigns window.nostr, so the
 * test mounts a minimal window (EventTarget-backed) and imports the module to
 * run it, then inspects the installed surface and its request wiring.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

let nostr;
const events = new EventTarget();

before(async () => {
  global.window = {
    addEventListener: (...a) => events.addEventListener(...a),
    removeEventListener: (...a) => events.removeEventListener(...a),
    dispatchEvent: (e) => events.dispatchEvent(e)
  };
  // Running the IIFE installs window.nostr.
  await import('../src/nostr-provider.js');
  nostr = global.window.nostr;
});

describe('provider surface (honest feature-detection)', () => {
  it('exposes exactly getPublicKey, signEvent and nip44', () => {
    assert.deepEqual(Object.keys(nostr).sort(), ['getPublicKey', 'nip44', 'signEvent']);
  });

  it('exposes nip44.encrypt and nip44.decrypt as functions', () => {
    assert.equal(typeof nostr.nip44.encrypt, 'function');
    assert.equal(typeof nostr.nip44.decrypt, 'function');
  });

  it('does NOT expose nip04 (deprecated scheme is not shipped)', () => {
    assert.equal('nip04' in nostr, false);
    assert.equal(nostr.nip04, undefined);
  });

  it('does NOT expose getRelays (no relay list is held)', () => {
    assert.equal('getRelays' in nostr, false);
    assert.equal(nostr.getRelays, undefined);
  });

  it('getPublicKey and signEvent are async functions', () => {
    assert.equal(typeof nostr.getPublicKey, 'function');
    assert.equal(typeof nostr.signEvent, 'function');
  });
});

describe('signEvent input validation (before any signing)', () => {
  // These reject synchronously inside the provider, never reaching the wire,
  // so no response listener is needed.
  it('rejects a non-object event', async () => {
    await assert.rejects(() => nostr.signEvent(null), /Event must be an object/);
    await assert.rejects(() => nostr.signEvent('nope'), /Event must be an object/);
  });

  it('rejects a missing/typed kind', async () => {
    await assert.rejects(() => nostr.signEvent({ created_at: 1, tags: [], content: '' }), /kind must be a number/);
  });

  it('rejects a missing created_at', async () => {
    await assert.rejects(() => nostr.signEvent({ kind: 1, tags: [], content: '' }), /created_at must be a number/);
  });

  it('rejects non-array tags', async () => {
    await assert.rejects(() => nostr.signEvent({ kind: 1, created_at: 1, tags: 'x', content: '' }), /tags must be an array/);
  });

  it('rejects non-string content', async () => {
    await assert.rejects(() => nostr.signEvent({ kind: 1, created_at: 1, tags: [], content: 5 }), /content must be a string/);
  });
});

describe('provider request wiring (podkey-request CustomEvent)', () => {
  /**
   * Capture the next podkey-request the provider emits, reply to it with the
   * matching id, and return the request detail for assertions.
   */
  function captureRequest (reply) {
    return new Promise((resolve) => {
      const handler = (e) => {
        global.window.removeEventListener('podkey-request', handler);
        const detail = e.detail;
        // Respond on the next tick so the provider's listener is registered.
        queueMicrotask(() => {
          global.window.dispatchEvent(new CustomEvent('podkey-response', {
            detail: { id: detail.id, result: reply(detail) }
          }));
        });
        resolve(detail);
      };
      global.window.addEventListener('podkey-request', handler);
    });
  }

  it('getPublicKey dispatches a GET_PUBLIC_KEY request and resolves the response', async () => {
    const reqP = captureRequest(() => 'deadbeef'.repeat(8));
    const resP = nostr.getPublicKey();
    const req = await reqP;
    assert.equal(req.type, 'GET_PUBLIC_KEY');
    assert.ok(req.id, 'request must carry a correlation id');
    assert.equal(await resP, 'deadbeef'.repeat(8));
  });

  it('signEvent forwards the validated event under SIGN_EVENT', async () => {
    const event = { kind: 1, created_at: 1700000000, tags: [['t', 'x']], content: 'gm' };
    const reqP = captureRequest((d) => ({ ...d.event, id: 'a'.repeat(64), pubkey: 'b'.repeat(64), sig: 'c'.repeat(128) }));
    const resP = nostr.signEvent(event);
    const req = await reqP;
    assert.equal(req.type, 'SIGN_EVENT');
    assert.deepEqual(req.event, event);
    const signed = await resP;
    assert.equal(signed.sig.length, 128);
  });

  it('nip44.encrypt dispatches NIP44_ENCRYPT with pubkey + plaintext (field is "pubkey")', async () => {
    const reqP = captureRequest(() => 'BASE64PAYLOAD');
    const resP = nostr.nip44.encrypt('f'.repeat(64), 'secret');
    const req = await reqP;
    assert.equal(req.type, 'NIP44_ENCRYPT');
    assert.equal(req.pubkey, 'f'.repeat(64));
    assert.equal(req.plaintext, 'secret');
    assert.equal('peer' in req, false, 'the reconciled field name is "pubkey", not "peer"');
    assert.equal(await resP, 'BASE64PAYLOAD');
  });

  it('nip44.decrypt dispatches NIP44_DECRYPT with pubkey + ciphertext', async () => {
    const reqP = captureRequest(() => 'plaintext-out');
    const resP = nostr.nip44.decrypt('f'.repeat(64), 'BASE64PAYLOAD');
    const req = await reqP;
    assert.equal(req.type, 'NIP44_DECRYPT');
    assert.equal(req.pubkey, 'f'.repeat(64));
    assert.equal(req.ciphertext, 'BASE64PAYLOAD');
    assert.equal(await resP, 'plaintext-out');
  });

  it('propagates a background error back to the caller as a rejection', async () => {
    const handler = (e) => {
      global.window.removeEventListener('podkey-request', handler);
      queueMicrotask(() => {
        global.window.dispatchEvent(new CustomEvent('podkey-response', {
          detail: { id: e.detail.id, error: 'User denied permission' }
        }));
      });
    };
    global.window.addEventListener('podkey-request', handler);
    await assert.rejects(() => nostr.getPublicKey(), /User denied permission/);
  });
});
