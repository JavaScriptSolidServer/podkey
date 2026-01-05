/**
 * Podkey - Cryptographic operations for Nostr keys
 * Uses noble-secp256k1 for all crypto operations
 */

import * as secp256k1 from '@noble/secp256k1';
import { schnorr } from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Set up hash functions for secp256k1 (required in v3+)
// @noble/secp256k1 v3+ requires explicit hash function assignment for sync methods
secp256k1.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
secp256k1.hashes.sha256 = sha256;

/**
 * Generate a new Nostr keypair
 * @returns {Promise<{privateKey: string, publicKey: string}>} 64-char hex keys
 */
export async function generateKeypair () {
  // Generate random 32-byte private key
  // In @noble/secp256k1 v3.0.0, use randomSecretKey instead of randomPrivateKey
  const privateKeyBytes = secp256k1.utils.randomSecretKey();
  const privateKey = bytesToHex(privateKeyBytes);

  // Derive public key
  const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes);
  // Remove the 02/03 prefix byte for Nostr format (x-only pubkey)
  const publicKey = bytesToHex(publicKeyBytes.slice(1));

  // Validate: both must be 64-char hex
  if (privateKey.length !== 64 || publicKey.length !== 64) {
    throw new Error('Invalid key generation: keys must be 64-char hex');
  }

  return { privateKey, publicKey };
}

/**
 * Get public key from private key
 * @param {string} privateKeyHex - 64-char hex private key
 * @returns {string} 64-char hex public key
 */
export function getPublicKey (privateKeyHex) {
  validatePrivateKey(privateKeyHex);

  const privateKeyBytes = hexToBytes(privateKeyHex);
  const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes);

  // Remove prefix byte for Nostr format
  return bytesToHex(publicKeyBytes.slice(1));
}

/**
 * Sign a Nostr event
 * @param {object} event - Unsigned Nostr event
 * @param {string} privateKeyHex - 64-char hex private key
 * @returns {Promise<object>} Signed event with id and sig
 */
export async function signEvent (event, privateKeyHex) {
  validatePrivateKey(privateKeyHex);

  // Get public key first (needed for event hash calculation)
  const pubkey = getPublicKey(privateKeyHex);

  // Calculate event ID (sha256 of serialized event)
  // Must include pubkey in the hash according to NIP-01
  const eventId = getEventHash({ ...event, pubkey });

  // Sign the event ID (must convert hex string to bytes)
  // Use schnorr.sign for Nostr-compatible Schnorr signatures
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const eventIdBytes = hexToBytes(eventId);
  const signatureBytes = schnorr.sign(eventIdBytes, privateKeyBytes);
  const signature = bytesToHex(signatureBytes);

  // Validate signature is 128-char hex (64 bytes)
  if (signature.length !== 128) {
    throw new Error('Invalid signature length');
  }

  // Ensure all fields are strings (Nostr spec requires this)
  return {
    ...event,
    id: String(eventId),
    pubkey: String(pubkey),
    sig: String(signature)
  };
}

/**
 * Verify a signed Nostr event
 * @param {object} event - Signed event
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifySignature (event) {
  try {
    const { id, pubkey, sig } = event;

    if (!id || !pubkey || !sig) return false;
    if (pubkey.length !== 64 || sig.length !== 128) return false;

    // Reconstruct full public key with prefix
    const pubkeyBytes = hexToBytes('02' + pubkey);
    const signatureBytes = hexToBytes(sig);
    const messageBytes = hexToBytes(id);

    return schnorr.verify(signatureBytes, messageBytes, pubkeyBytes.slice(1));
  } catch (error) {
    return false;
  }
}

/**
 * Calculate event hash (ID)
 * @param {object} event - Event object
 * @returns {string} 64-char hex event ID
 */
export function getEventHash (event) {
  // Serialize event according to NIP-01
  const serialized = JSON.stringify([
    0, // Reserved for future use
    event.pubkey || '',
    event.created_at,
    event.kind,
    event.tags || [],
    event.content || ''
  ]);

  const hash = sha256(new TextEncoder().encode(serialized));
  return bytesToHex(hash);
}

/**
 * Validate private key format (64-char hex)
 * @param {string} privateKey - Private key to validate
 * @throws {Error} If invalid
 */
function validatePrivateKey (privateKey) {
  if (typeof privateKey !== 'string') {
    throw new Error('Private key must be a string');
  }

  if (privateKey.length !== 64) {
    throw new Error('Private key must be 64-char hex (32 bytes)');
  }

  if (!/^[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error('Private key must be valid hexadecimal');
  }
}

/**
 * Validate public key format (64-char hex)
 * @param {string} publicKey - Public key to validate
 * @returns {boolean} True if valid
 */
export function isValidPublicKey (publicKey) {
  if (typeof publicKey !== 'string') return false;
  if (publicKey.length !== 64) return false;
  return /^[0-9a-fA-F]{64}$/.test(publicKey);
}

/**
 * Convert private key to nsec format (Bech32)
 * @param {string} privateKeyHex - 64-char hex private key
 * @returns {string} nsec1... format
 */
export function privateKeyToNsec (privateKeyHex) {
  // TODO: Implement bech32 encoding
  // For now, return hex with nsec prefix as placeholder
  return `nsec_${privateKeyHex}`;
}

/**
 * Convert nsec to private key hex
 * @param {string} nsec - nsec1... format
 * @returns {string} 64-char hex private key
 */
export function nsecToPrivateKey (nsec) {
  // TODO: Implement bech32 decoding
  // For now, strip nsec_ prefix as placeholder
  return nsec.replace(/^nsec_/, '');
}

/**
 * Convert public key to npub format (Bech32)
 * @param {string} publicKeyHex - 64-char hex public key
 * @returns {string} npub1... format
 */
export function publicKeyToNpub (publicKeyHex) {
  // TODO: Implement bech32 encoding
  return `npub_${publicKeyHex}`;
}
