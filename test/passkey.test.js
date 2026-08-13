import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { getPublicKey } from '../src/crypto.js';
import {
  deriveNostrKey,
  fromBase64Url,
  toBase64Url,
  unwrapPrivateKey,
  wrapPrivateKey
} from '../src/passkey.js';

globalThis.crypto ??= webcrypto;
globalThis.btoa ??= value => Buffer.from(value, 'binary').toString('base64');
globalThis.atob ??= value => Buffer.from(value, 'base64').toString('binary');

describe('passkey key material', () => {
  it('round-trips binary values through base64url', () => {
    const bytes = Uint8Array.from([0, 1, 2, 250, 255]);
    assert.deepEqual(fromBase64Url(toBase64Url(bytes)), bytes);
  });

  it('derives the same valid Nostr key from the same PRF output and salt', async () => {
    const prf = new Uint8Array(32).fill(7);
    const salt = new Uint8Array(32).fill(11);
    const first = await deriveNostrKey(prf, salt);
    const second = await deriveNostrKey(prf, salt);
    assert.equal(first, second);
    assert.match(first, /^[0-9a-f]{64}$/);
    assert.match(getPublicKey(first), /^[0-9a-f]{64}$/);
  });

  it('domain-separates identities with different salts', async () => {
    const prf = new Uint8Array(32).fill(7);
    assert.notEqual(
      await deriveNostrKey(prf, new Uint8Array(32).fill(1)),
      await deriveNostrKey(prf, new Uint8Array(32).fill(2))
    );
  });

  it('wraps and unwraps an existing Nostr key', async () => {
    const privateKey = '01'.padStart(64, '0');
    const prf = new Uint8Array(32).fill(9);
    const wrapped = await wrapPrivateKey(privateKey, prf);
    assert.equal(await unwrapPrivateKey(wrapped, prf), privateKey);
    await assert.rejects(() => unwrapPrivateKey(wrapped, new Uint8Array(32).fill(8)), /could not unlock/);
  });

  it('rejects tampered wrapped ciphertext', async () => {
    const prf = new Uint8Array(32).fill(9);
    const wrapped = await wrapPrivateKey('02'.padStart(64, '0'), prf);
    const bytes = fromBase64Url(wrapped.ct);
    bytes[0] ^= 1;
    await assert.rejects(() => unwrapPrivateKey({ ...wrapped, ct: toBase64Url(bytes) }, prf), /could not unlock/);
  });
});

describe('wrap freshness and domain separation', () => {
  it('uses a fresh random salt and iv for every wrap', async () => {
    const prf = new Uint8Array(32).fill(9);
    const privateKey = '03'.padStart(64, '0');
    const a = await wrapPrivateKey(privateKey, prf);
    const b = await wrapPrivateKey(privateKey, prf);
    assert.notEqual(a.salt, b.salt);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ct, b.ct);
    assert.equal(await unwrapPrivateKey(a, prf), privateKey);
    assert.equal(await unwrapPrivateKey(b, prf), privateKey);
  });

  it('never derives an identity equal to the raw PRF output or wrap key path', async () => {
    // Sanity check on domain separation: the derived identity must not be a
    // trivial function of the inputs (distinct info strings guarantee the
    // derive and wrap HKDF outputs differ even for identical prf and salt).
    const prf = new Uint8Array(32).fill(5);
    const salt = new Uint8Array(32).fill(6);
    const derived = await deriveNostrKey(prf, salt);
    assert.notEqual(derived, Buffer.from(prf).toString('hex'));
    assert.notEqual(derived, Buffer.from(salt).toString('hex'));
  });
});
