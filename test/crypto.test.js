/**
 * Tests for Podkey cryptographic functions
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { 
  generateKeypair, 
  getPublicKey, 
  signEvent, 
  verifySignature,
  getEventHash,
  isValidPublicKey
} from '../src/crypto.js';

describe('Crypto Functions', () => {
  describe('generateKeypair', () => {
    it('should generate a valid keypair', async () => {
      const keypair = await generateKeypair();
      
      assert(keypair, 'Keypair should be returned');
      assert(keypair.privateKey, 'Private key should exist');
      assert(keypair.publicKey, 'Public key should exist');
      assert.strictEqual(keypair.privateKey.length, 64, 'Private key should be 64 chars');
      assert.strictEqual(keypair.publicKey.length, 64, 'Public key should be 64 chars');
      assert(/^[0-9a-fA-F]{64}$/.test(keypair.privateKey), 'Private key should be hex');
      assert(/^[0-9a-fA-F]{64}$/.test(keypair.publicKey), 'Public key should be hex');
    });

    it('should generate different keypairs each time', async () => {
      const keypair1 = await generateKeypair();
      const keypair2 = await generateKeypair();
      
      assert.notStrictEqual(keypair1.privateKey, keypair2.privateKey, 'Private keys should differ');
      assert.notStrictEqual(keypair1.publicKey, keypair2.publicKey, 'Public keys should differ');
    });
  });

  describe('getPublicKey', () => {
    it('should derive public key from private key', async () => {
      const keypair = await generateKeypair();
      const derivedPublicKey = getPublicKey(keypair.privateKey);
      
      assert.strictEqual(derivedPublicKey, keypair.publicKey, 'Derived public key should match');
      assert.strictEqual(derivedPublicKey.length, 64, 'Public key should be 64 chars');
    });

    it('should throw error for invalid private key', () => {
      assert.throws(() => getPublicKey('invalid'), /Private key must be/);
      assert.throws(() => getPublicKey('123'), /Private key must be/);
      assert.throws(() => getPublicKey('x'.repeat(64)), /Private key must be valid hexadecimal/);
    });
  });

  describe('signEvent', () => {
    it('should sign an event correctly', async () => {
      const keypair = await generateKeypair();
      const event = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Test event'
      };

      const signed = await signEvent(event, keypair.privateKey);
      
      assert(signed.id, 'Event should have id');
      assert(signed.pubkey, 'Event should have pubkey');
      assert(signed.sig, 'Event should have signature');
      assert.strictEqual(signed.id.length, 64, 'Event ID should be 64 chars');
      assert.strictEqual(signed.pubkey.length, 64, 'Pubkey should be 64 chars');
      assert.strictEqual(signed.sig.length, 128, 'Signature should be 128 chars');
      assert.strictEqual(signed.pubkey, keypair.publicKey, 'Pubkey should match');
    });

    it('should include pubkey in event hash', async () => {
      const keypair = await generateKeypair();
      const event = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Test'
      };

      const signed = await signEvent(event, keypair.privateKey);
      const hashWithPubkey = getEventHash({ ...event, pubkey: keypair.publicKey });
      
      assert.strictEqual(signed.id, hashWithPubkey, 'Event ID should match hash with pubkey');
    });
  });

  describe('verifySignature', () => {
    it('should verify a valid signature', async () => {
      const keypair = await generateKeypair();
      const event = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Test event'
      };

      const signed = await signEvent(event, keypair.privateKey);
      const isValid = await verifySignature(signed);
      
      assert.strictEqual(isValid, true, 'Signature should be valid');
    });

    it('should reject invalid signature', async () => {
      const keypair = await generateKeypair();
      const event = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Test event',
        id: 'a'.repeat(64),
        pubkey: keypair.publicKey,
        sig: 'b'.repeat(128) // Invalid signature
      };

      const isValid = await verifySignature(event);
      assert.strictEqual(isValid, false, 'Invalid signature should be rejected');
    });
  });

  describe('getEventHash', () => {
    it('should generate consistent hashes', () => {
      const event = {
        kind: 1,
        created_at: 1234567890,
        tags: [],
        content: 'Test',
        pubkey: 'a'.repeat(64)
      };

      const hash1 = getEventHash(event);
      const hash2 = getEventHash(event);
      
      assert.strictEqual(hash1, hash2, 'Hashes should be consistent');
      assert.strictEqual(hash1.length, 64, 'Hash should be 64 chars');
    });

    it('should include pubkey in hash', () => {
      const event1 = {
        kind: 1,
        created_at: 1234567890,
        tags: [],
        content: 'Test',
        pubkey: 'a'.repeat(64)
      };
      
      const event2 = {
        ...event1,
        pubkey: 'b'.repeat(64)
      };

      const hash1 = getEventHash(event1);
      const hash2 = getEventHash(event2);
      
      assert.notStrictEqual(hash1, hash2, 'Different pubkeys should produce different hashes');
    });
  });

  describe('isValidPublicKey', () => {
    it('should validate correct public keys', () => {
      assert.strictEqual(isValidPublicKey('a'.repeat(64)), true);
      assert.strictEqual(isValidPublicKey('0123456789abcdef'.repeat(4)), true);
    });

    it('should reject invalid public keys', () => {
      assert.strictEqual(isValidPublicKey(''), false);
      assert.strictEqual(isValidPublicKey('a'.repeat(63)), false);
      assert.strictEqual(isValidPublicKey('a'.repeat(65)), false);
      assert.strictEqual(isValidPublicKey('g'.repeat(64)), false); // Invalid hex
      assert.strictEqual(isValidPublicKey(null), false);
      assert.strictEqual(isValidPublicKey(undefined), false);
    });
  });
});
