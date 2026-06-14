/**
 * Podkey - NIP-44 (v2) encryption / decryption
 *
 * Implements the current NIP-44 versioned encryption scheme (version 0x02):
 *   conversation key = hkdf_extract(IKM = ECDH(priv, pub).x, salt = "nip44-v2")
 *   per-message keys = hkdf_expand(conversation_key, info = nonce, L = 76)
 *                        -> chacha_key (32) ‖ chacha_nonce (12) ‖ hmac_key (32)
 *   ciphertext       = chacha20(chacha_key, chacha_nonce, pad(plaintext))
 *   mac              = hmac_sha256(hmac_key, aad = nonce ‖ ciphertext)
 *   payload          = base64( version(0x02) ‖ nonce(32) ‖ ciphertext ‖ mac(32) )
 *
 * Uses the same vetted @noble primitives the rest of the extension depends on:
 *   - @noble/secp256k1     : ECDH shared secret
 *   - @noble/hashes        : hkdf, hmac, sha256
 *   - @noble/ciphers       : chacha20 (raw, unauthenticated, IETF nonce)
 *
 * Spec: https://github.com/nostr-protocol/nips/blob/master/44.md
 */

import { getSharedSecret } from '@noble/secp256k1';
import { hkdf, extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { chacha20 } from '@noble/ciphers/chacha.js';

const VERSION = 2;
const SALT = utf8ToBytes('nip44-v2');
const MIN_PLAINTEXT_SIZE = 1; // 1 byte (NIP-44 forbids empty plaintext)
const MAX_PLAINTEXT_SIZE = 65535; // 64KB - 1

/**
 * Compute the NIP-44 conversation key for a (private, public) pair.
 * conversation_key = hkdf_extract(IKM = sharedX, salt = "nip44-v2")
 *
 * @param {string} privateKeyHex - 64-char hex private key (the user's)
 * @param {string} peerPublicKeyHex - 64-char hex x-only public key (the peer's)
 * @returns {Uint8Array} 32-byte conversation key
 */
export function getConversationKey (privateKeyHex, peerPublicKeyHex) {
  validateHexKey(privateKeyHex, 'private');
  validateHexKey(peerPublicKeyHex, 'public');

  // ECDH: prefix the x-only Nostr pubkey with 0x02 to get a compressed point.
  // getSharedSecret returns a 33-byte compressed point; bytes [1..33] are the
  // shared X coordinate used as the HKDF input keying material.
  const shared = getSharedSecret(hexToBytes(privateKeyHex), hexToBytes('02' + peerPublicKeyHex));
  const sharedX = shared.subarray(1, 33);

  return hkdfExtract(sha256, sharedX, SALT);
}

/**
 * Derive the per-message keys from the conversation key and nonce.
 * @param {Uint8Array} conversationKey - 32-byte conversation key
 * @param {Uint8Array} nonce - 32-byte random nonce
 * @returns {{ chachaKey: Uint8Array, chachaNonce: Uint8Array, hmacKey: Uint8Array }}
 */
function getMessageKeys (conversationKey, nonce) {
  if (conversationKey.length !== 32) {
    throw new Error('Invalid conversation key length');
  }
  if (nonce.length !== 32) {
    throw new Error('Invalid nonce length');
  }

  const keys = hkdfExpand(sha256, conversationKey, nonce, 76);
  return {
    chachaKey: keys.subarray(0, 32),
    chachaNonce: keys.subarray(32, 44),
    hmacKey: keys.subarray(44, 76)
  };
}

/**
 * Calculate the padded length for a given plaintext length (power-of-two
 * bucketing, minimum 32 bytes) per the NIP-44 padding scheme.
 * @param {number} len - unpadded plaintext length in bytes
 * @returns {number} padded length
 */
function calcPaddedLen (len) {
  if (!Number.isInteger(len) || len < 1) {
    throw new Error('Expected positive integer length');
  }
  if (len <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

/**
 * Pad plaintext: u16 big-endian length prefix ‖ utf8(plaintext) ‖ zero padding.
 * @param {string} plaintext
 * @returns {Uint8Array}
 */
function pad (plaintext) {
  const unpadded = utf8ToBytes(plaintext);
  const unpaddedLen = unpadded.length;
  if (unpaddedLen < MIN_PLAINTEXT_SIZE || unpaddedLen > MAX_PLAINTEXT_SIZE) {
    throw new Error('Invalid plaintext length');
  }

  const prefix = new Uint8Array(2);
  new DataView(prefix.buffer).setUint16(0, unpaddedLen, false); // big-endian

  const padded = new Uint8Array(calcPaddedLen(unpaddedLen));
  padded.set(unpadded);

  return concatBytes(prefix, padded);
}

/**
 * Unpad a decrypted buffer back to the original plaintext string.
 * @param {Uint8Array} padded - prefix ‖ plaintext ‖ zero padding
 * @returns {string}
 */
function unpad (padded) {
  const unpaddedLen = new DataView(padded.buffer, padded.byteOffset, 2).getUint16(0, false);
  const unpadded = padded.subarray(2, 2 + unpaddedLen);

  if (
    unpaddedLen < MIN_PLAINTEXT_SIZE ||
    unpaddedLen > MAX_PLAINTEXT_SIZE ||
    unpadded.length !== unpaddedLen ||
    padded.length !== 2 + calcPaddedLen(unpaddedLen)
  ) {
    throw new Error('Invalid padding');
  }

  return new TextDecoder().decode(unpadded);
}

/**
 * HMAC-SHA256 with the nonce as associated data, per NIP-44:
 *   mac = hmac_sha256(key, aad ‖ message) where aad = nonce
 * @param {Uint8Array} key - 32-byte hmac key
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} aad - 32-byte nonce
 * @returns {Uint8Array} 32-byte mac
 */
function hmacAad (key, ciphertext, aad) {
  if (aad.length !== 32) {
    throw new Error('AAD (nonce) must be 32 bytes');
  }
  return hmac(sha256, key, concatBytes(aad, ciphertext));
}

/**
 * Constant-time comparison of two byte arrays.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function equalBytes (a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Encrypt plaintext with NIP-44 v2.
 * @param {string} plaintext - message to encrypt
 * @param {Uint8Array} conversationKey - 32-byte conversation key
 * @param {Uint8Array} [nonce] - optional 32-byte nonce (random if omitted)
 * @returns {string} base64 NIP-44 payload
 */
export function encrypt (plaintext, conversationKey, nonce = randomBytes(32)) {
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce);
  const padded = pad(plaintext);
  const ciphertext = chacha20(chachaKey, chachaNonce, padded);
  const mac = hmacAad(hmacKey, ciphertext, nonce);

  const payload = concatBytes(new Uint8Array([VERSION]), nonce, ciphertext, mac);
  return base64Encode(payload);
}

/**
 * Decrypt a NIP-44 v2 base64 payload.
 * @param {string} payload - base64 NIP-44 payload
 * @param {Uint8Array} conversationKey - 32-byte conversation key
 * @returns {string} decrypted plaintext
 */
export function decrypt (payload, conversationKey) {
  if (typeof payload !== 'string' || payload.length === 0) {
    throw new Error('Invalid payload');
  }
  // Reject NIP-44 "encoded as #..." marker payloads explicitly.
  if (payload[0] === '#') {
    throw new Error('Unsupported encryption version');
  }

  const data = base64Decode(payload);
  const version = data[0];
  if (version !== VERSION) {
    throw new Error(`Unknown encryption version: ${version}`);
  }

  // version(1) ‖ nonce(32) ‖ ciphertext(>=32) ‖ mac(32)
  if (data.length < 1 + 32 + 32 + 32) {
    throw new Error('Invalid payload length');
  }

  const nonce = data.subarray(1, 33);
  const ciphertext = data.subarray(33, data.length - 32);
  const mac = data.subarray(data.length - 32);

  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce);
  const calculatedMac = hmacAad(hmacKey, ciphertext, nonce);
  if (!equalBytes(calculatedMac, mac)) {
    throw new Error('Invalid MAC');
  }

  const padded = chacha20(chachaKey, chachaNonce, ciphertext);
  return unpad(padded);
}

/**
 * Encrypt using raw key material (convenience for the background handler):
 * derives the conversation key from (privateKeyHex, peerPublicKeyHex) first.
 * @param {string} privateKeyHex
 * @param {string} peerPublicKeyHex
 * @param {string} plaintext
 * @returns {string} base64 NIP-44 payload
 */
export function encryptWithKeys (privateKeyHex, peerPublicKeyHex, plaintext) {
  const conversationKey = getConversationKey(privateKeyHex, peerPublicKeyHex);
  return encrypt(plaintext, conversationKey);
}

/**
 * Decrypt using raw key material (convenience for the background handler).
 * @param {string} privateKeyHex
 * @param {string} peerPublicKeyHex
 * @param {string} payload - base64 NIP-44 payload
 * @returns {string} decrypted plaintext
 */
export function decryptWithKeys (privateKeyHex, peerPublicKeyHex, payload) {
  const conversationKey = getConversationKey(privateKeyHex, peerPublicKeyHex);
  return decrypt(payload, conversationKey);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomBytes (n) {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return bytes;
}

function validateHexKey (key, kind) {
  if (typeof key !== 'string' || !/^[0-9a-fA-F]{64}$/.test(key)) {
    throw new Error(`Invalid ${kind} key: must be 64-char hex`);
  }
}

function base64Encode (bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64Decode (str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Re-export hashing helpers used by callers/tests for convenience.
export { bytesToHex, hexToBytes, hkdf };
