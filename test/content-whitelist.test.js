/**
 * Tests for the content-script message-type whitelist (injected.js,
 * security/whitelist-message-types #19).
 *
 * The content script bridges page CustomEvents to chrome.runtime. It must:
 *   - forward ONLY the four NIP-07 message types, rejecting anything else with
 *     "Unknown request type" and never calling sendMessage for it
 *   - forward ONLY known-safe fields per type (no arbitrary page-supplied props
 *     reach the background), always appending the real page origin
 *
 * injected.js runs at import time against the DOM and chrome.runtime, so the
 * test mounts minimal window/document/chrome and then drives it via the
 * podkey-request / podkey-response CustomEvents the provider uses.
 */

import { describe, it, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const ORIGIN = 'https://app.test';
const bus = new EventTarget();
const forwarded = [];

before(async () => {
  global.window = {
    addEventListener: (...a) => bus.addEventListener(...a),
    removeEventListener: (...a) => bus.removeEventListener(...a),
    dispatchEvent: (e) => bus.dispatchEvent(e),
    location: { origin: ORIGIN }
  };
  global.document = {
    createElement: () => ({ set src (_v) {}, set onload (_v) {}, set onerror (_v) {}, remove () {} }),
    head: { appendChild () {} },
    documentElement: { appendChild () {} }
  };
  global.chrome = {
    runtime: {
      getURL: (p) => 'chrome-extension://test/' + p,
      sendMessage: async (message) => {
        forwarded.push(message);
        if (message.type === 'GET_PUBLIC_KEY') return 'a'.repeat(64);
        if (message.type === 'SIGN_EVENT') return { ...message.event, id: 'i'.repeat(64), sig: 's'.repeat(128) };
        return 'OK';
      },
      lastError: null
    }
  };
  await import('../src/injected.js');
});

beforeEach(() => { forwarded.length = 0; });

let seq = 0;
/** Dispatch a podkey-request and resolve with the matching podkey-response. */
function request (detail) {
  const id = `req-${++seq}`;
  return new Promise((resolve) => {
    const handler = (e) => {
      if (e.detail.id !== id) return;
      bus.removeEventListener('podkey-response', handler);
      resolve(e.detail);
    };
    bus.addEventListener('podkey-response', handler);
    bus.dispatchEvent(new CustomEvent('podkey-request', { detail: { id, ...detail } }));
  });
}

describe('content-script whitelist', () => {
  it('forwards GET_PUBLIC_KEY and returns the result', async () => {
    const res = await request({ type: 'GET_PUBLIC_KEY' });
    assert.equal(res.result, 'a'.repeat(64));
    assert.equal(forwarded.length, 1);
    assert.equal(forwarded[0].type, 'GET_PUBLIC_KEY');
  });

  it('forwards SIGN_EVENT, NIP44_ENCRYPT and NIP44_DECRYPT', async () => {
    await request({ type: 'SIGN_EVENT', event: { kind: 1, created_at: 1, tags: [], content: 'x' } });
    await request({ type: 'NIP44_ENCRYPT', pubkey: 'f'.repeat(64), plaintext: 'hi' });
    await request({ type: 'NIP44_DECRYPT', pubkey: 'f'.repeat(64), ciphertext: 'BASE64' });
    assert.deepEqual(forwarded.map((m) => m.type), ['SIGN_EVENT', 'NIP44_ENCRYPT', 'NIP44_DECRYPT']);
  });

  it('rejects an unknown type and never forwards it', async () => {
    const res = await request({ type: 'EXPORT_PRIVATE_KEY' });
    assert.deepEqual(res, { id: res.id, error: 'Unknown request type' });
    assert.equal(forwarded.length, 0, 'an unknown type must not reach the background');
  });

  it('rejects NIP-98 header type on the NIP-07 channel (separate channel only)', async () => {
    // CREATE_NIP98_AUTH_HEADER is intentionally not in the NIP-07 whitelist;
    // it has its own podkey-nip98-request channel.
    const res = await request({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://x/', method: 'GET' });
    assert.equal(res.error, 'Unknown request type');
    assert.equal(forwarded.length, 0);
  });

  it('always appends the page origin to forwarded messages', async () => {
    await request({ type: 'GET_PUBLIC_KEY' });
    assert.equal(forwarded[0].origin, ORIGIN);
  });
});

describe('content-script field stripping (only safe fields forwarded)', () => {
  it('SIGN_EVENT forwards only { event, type, origin } — drops injected extras', async () => {
    await request({
      type: 'SIGN_EVENT',
      event: { kind: 1, created_at: 1, tags: [], content: 'x' },
      privateKey: 'attacker-supplied', // must NOT be forwarded
      origin: 'https://spoofed.evil' // page-supplied origin must be overridden
    });
    const msg = forwarded[0];
    assert.deepEqual(Object.keys(msg).sort(), ['event', 'origin', 'type']);
    assert.equal(msg.origin, ORIGIN, 'origin must be the real page origin, not a spoofed one');
    assert.equal('privateKey' in msg, false);
  });

  it('NIP44_ENCRYPT forwards only pubkey + plaintext (field is "pubkey", not "peer")', async () => {
    await request({
      type: 'NIP44_ENCRYPT', pubkey: 'f'.repeat(64), plaintext: 'secret',
      peer: 'should-be-dropped', extra: 'nope'
    });
    const msg = forwarded[0];
    assert.deepEqual(Object.keys(msg).sort(), ['origin', 'plaintext', 'pubkey', 'type']);
    assert.equal(msg.pubkey, 'f'.repeat(64));
    assert.equal(msg.plaintext, 'secret');
    assert.equal('peer' in msg, false);
    assert.equal('extra' in msg, false);
  });

  it('NIP44_DECRYPT forwards only pubkey + ciphertext', async () => {
    await request({ type: 'NIP44_DECRYPT', pubkey: 'f'.repeat(64), ciphertext: 'BASE64', junk: 1 });
    const msg = forwarded[0];
    assert.deepEqual(Object.keys(msg).sort(), ['ciphertext', 'origin', 'pubkey', 'type']);
    assert.equal('junk' in msg, false);
  });

  it('coerces NIP44 fields to strings', async () => {
    await request({ type: 'NIP44_ENCRYPT', pubkey: 123, plaintext: 456 });
    const msg = forwarded[0];
    assert.equal(typeof msg.pubkey, 'string');
    assert.equal(typeof msg.plaintext, 'string');
  });
});
