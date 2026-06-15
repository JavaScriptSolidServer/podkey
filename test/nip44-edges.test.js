/**
 * NIP-44 (v2) edge cases and security boundaries NOT already covered by
 * nip44.test.js (which owns the spec vectors and the basic round-trip).
 *
 * Focus here:
 *   - plaintext length bounds (1..65535): empty is rejected, max is allowed
 *   - key isolation: a payload does not decrypt under the wrong conversation key
 *   - malformed-payload rejection (too short to contain version+nonce+mac)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  getConversationKey, encrypt, decrypt, hexToBytes
} from '../src/nip44.js';
import { generateKeypair } from '../src/crypto.js';

describe('NIP-44 plaintext length bounds', () => {
  it('rejects empty plaintext (NIP-44 forbids 0-length)', async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const ck = getConversationKey(a.privateKey, b.publicKey);
    assert.throws(() => encrypt('', ck), /Invalid plaintext length/);
  });

  it('encrypts/decrypts a single-byte plaintext (min boundary)', async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const ck = getConversationKey(a.privateKey, b.publicKey);
    assert.equal(decrypt(encrypt('x', ck), ck), 'x');
  });

  it('encrypts/decrypts the maximum-length plaintext (65535 bytes)', async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const ck = getConversationKey(a.privateKey, b.publicKey);
    const max = 'a'.repeat(65535);
    assert.equal(decrypt(encrypt(max, ck), ck), max);
  });

  it('rejects plaintext above the maximum length', async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const ck = getConversationKey(a.privateKey, b.publicKey);
    assert.throws(() => encrypt('a'.repeat(65536), ck), /Invalid plaintext length/);
  });
});

describe('NIP-44 key isolation', () => {
  it('a third party with a different conversation key cannot decrypt', async () => {
    const alice = await generateKeypair();
    const bob = await generateKeypair();
    const eve = await generateKeypair();

    const ckAB = getConversationKey(alice.privateKey, bob.publicKey);
    const payload = encrypt('for bob only', ckAB);

    // Eve derives a conversation key with alice — different shared secret.
    const ckAE = getConversationKey(alice.privateKey, eve.publicKey);
    assert.throws(() => decrypt(payload, ckAE), /Invalid MAC/,
      'wrong conversation key must fail the MAC check, not silently decrypt');
  });

  it('the same conversation key from both peers decrypts (sanity, no key reuse leak)', async () => {
    const alice = await generateKeypair();
    const bob = await generateKeypair();
    const ckA = getConversationKey(alice.privateKey, bob.publicKey);
    const ckB = getConversationKey(bob.privateKey, alice.publicKey);
    const payload = encrypt('round', ckA);
    assert.equal(decrypt(payload, ckB), 'round');
  });
});

describe('NIP-44 malformed payload rejection', () => {
  it('rejects a payload too short to hold version+nonce+ciphertext+mac', () => {
    const ck = hexToBytes('11'.repeat(32));
    // base64 of a single version byte 0x02 — far below the minimum frame size.
    const tooShort = btoa(String.fromCharCode(2));
    assert.throws(() => decrypt(tooShort, ck));
  });

  it('rejects non-base64 garbage', () => {
    const ck = hexToBytes('22'.repeat(32));
    assert.throws(() => decrypt('!!!not base64!!!', ck));
  });
});
