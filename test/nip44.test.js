/**
 * Tests for Podkey NIP-44 (v2) encryption.
 *
 * Mirrors the structure of crypto.test.js and adds official NIP-44 spec
 * test vectors to prove the implementation matches the standard.
 * Vectors: https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  getConversationKey,
  encrypt,
  decrypt,
  encryptWithKeys,
  decryptWithKeys,
  bytesToHex,
  hexToBytes
} from '../src/nip44.js';
import { generateKeypair, getPublicKey } from '../src/crypto.js';

describe('NIP-44 (v2)', () => {
  describe('getConversationKey', () => {
    it('is symmetric: convKey(a, B) === convKey(b, A)', async () => {
      const alice = await generateKeypair();
      const bob = await generateKeypair();

      const fromAlice = getConversationKey(alice.privateKey, bob.publicKey);
      const fromBob = getConversationKey(bob.privateKey, alice.publicKey);

      assert.strictEqual(bytesToHex(fromAlice), bytesToHex(fromBob),
        'Conversation key must be identical from both sides');
      assert.strictEqual(fromAlice.length, 32, 'Conversation key must be 32 bytes');
    });

    it('matches the official NIP-44 spec test vector', () => {
      // From nip44.vectors.json -> v2.valid.get_conversation_key[0]
      const sec1 = '315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268';
      const pub2 = 'c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133';
      const expected = '3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1';

      const convKey = getConversationKey(sec1, pub2);
      assert.strictEqual(bytesToHex(convKey), expected,
        'Conversation key must match the NIP-44 spec vector');
    });

    it('rejects malformed keys', () => {
      assert.throws(() => getConversationKey('zz', 'a'.repeat(64)), /Invalid private key/);
      assert.throws(() => getConversationKey('a'.repeat(64), 'short'), /Invalid public key/);
    });
  });

  describe('official NIP-44 spec encrypt/decrypt vector', () => {
    // From nip44.vectors.json -> v2.valid.encrypt_decrypt[0]
    const conversationKey = hexToBytes('c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d');
    const nonce = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
    const plaintext = 'a';
    const payload = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb';

    it('encrypt with the spec nonce produces the spec payload', () => {
      assert.strictEqual(encrypt(plaintext, conversationKey, nonce), payload);
    });

    it('decrypt of the spec payload yields the spec plaintext', () => {
      assert.strictEqual(decrypt(payload, conversationKey), plaintext);
    });
  });

  describe('encrypt/decrypt round-trip', () => {
    it('round-trips a simple message', async () => {
      const alice = await generateKeypair();
      const bob = await generateKeypair();
      const plaintext = 'Hello from the DreamLab forum 👋';

      const convKeyAlice = getConversationKey(alice.privateKey, bob.publicKey);
      const convKeyBob = getConversationKey(bob.privateKey, alice.publicKey);

      const payload = encrypt(plaintext, convKeyAlice);
      assert.match(payload, /^[A-Za-z0-9+/]+=*$/, 'Payload should be base64');

      const decrypted = decrypt(payload, convKeyBob);
      assert.strictEqual(decrypted, plaintext, 'Decrypted text must match original');
    });

    it('produces a v2 payload (first byte 0x02)', async () => {
      const alice = await generateKeypair();
      const bob = await generateKeypair();
      const convKey = getConversationKey(alice.privateKey, bob.publicKey);

      const payload = encrypt('version check', convKey);
      const raw = Uint8Array.from(atob(payload), c => c.charCodeAt(0));
      assert.strictEqual(raw[0], 2, 'First byte of the payload must be version 0x02');
    });

    it('produces different payloads for the same plaintext (random nonce)', async () => {
      const alice = await generateKeypair();
      const bob = await generateKeypair();
      const convKey = getConversationKey(alice.privateKey, bob.publicKey);

      const a = encrypt('same message', convKey);
      const b = encrypt('same message', convKey);
      assert.notStrictEqual(a, b, 'Nonce randomization must yield distinct payloads');
      assert.strictEqual(decrypt(a, convKey), decrypt(b, convKey));
    });

    it('round-trips unicode and emoji', async () => {
      const alice = await generateKeypair();
      const bob = await generateKeypair();
      const convKey = getConversationKey(alice.privateKey, bob.publicKey);
      const plaintext = 'ünîcödé 测试 🔐 — NIP-44';

      assert.strictEqual(decrypt(encrypt(plaintext, convKey), convKey), plaintext);
    });

    it('round-trips a long message (padding buckets)', async () => {
      const alice = await generateKeypair();
      const bob = await generateKeypair();
      const convKey = getConversationKey(alice.privateKey, bob.publicKey);
      const plaintext = 'x'.repeat(5000);

      assert.strictEqual(decrypt(encrypt(plaintext, convKey), convKey), plaintext);
    });
  });

  describe('encryptWithKeys/decryptWithKeys (background path helpers)', () => {
    it('round-trips using raw key material', async () => {
      const alice = await generateKeypair();
      const bob = await generateKeypair();
      const plaintext = 'gift-wrapped DM payload';

      const payload = encryptWithKeys(alice.privateKey, bob.publicKey, plaintext);
      const decrypted = decryptWithKeys(bob.privateKey, alice.publicKey, payload);

      assert.strictEqual(decrypted, plaintext);
    });

    it('derived pubkeys match generated pubkeys', async () => {
      const alice = await generateKeypair();
      assert.strictEqual(getPublicKey(alice.privateKey), alice.publicKey);
    });
  });

  describe('tamper detection (HMAC)', () => {
    it('rejects a payload with a flipped ciphertext byte', async () => {
      const alice = await generateKeypair();
      const bob = await generateKeypair();
      const convKey = getConversationKey(alice.privateKey, bob.publicKey);

      const payload = encrypt('authentic message', convKey);
      const raw = Uint8Array.from(atob(payload), c => c.charCodeAt(0));
      raw[40] ^= 0xff; // flip a byte inside the ciphertext region
      let binary = '';
      for (const b of raw) binary += String.fromCharCode(b);
      const tampered = btoa(binary);

      assert.throws(() => decrypt(tampered, convKey), /Invalid MAC/);
    });

    it('rejects an unknown version byte', () => {
      const convKey = hexToBytes('00'.repeat(32));
      // version 0x01 (NIP-04-style marker is unsupported by NIP-44 v2)
      const bogus = btoa(String.fromCharCode(1) + 'x'.repeat(96));
      assert.throws(() => decrypt(bogus, convKey), /Unknown encryption version/);
    });
  });
});
