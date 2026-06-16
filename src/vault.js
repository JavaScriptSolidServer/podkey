/**
 * Podkey — encrypted-at-rest key vault.
 *
 * The private key is persisted ONLY as an AES-256-GCM ciphertext in
 * chrome.storage.local, wrapped by a key derived from the user's passphrase via
 * scrypt. Once unlocked, the plaintext key is cached in chrome.storage.session
 * (in-memory, browser-session scoped, see storage.js) so signing stays fast and
 * the disk never holds the raw key. A browser restart clears the session; the
 * user re-unlocks with their passphrase.
 *
 * The pure crypto (encryptPrivateKey / decryptPrivateKey) is split from the
 * chrome.storage I/O so it is unit-testable off-platform (test/vault.test.js).
 */

import { scrypt } from '@noble/hashes/scrypt';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';

const VAULT_KEY = 'podkey_vault';
const MIN_PASSPHRASE = 8;

// scrypt cost — interactive-login grade. Stored inside the blob so the
// parameters travel with the ciphertext and can be raised later without
// breaking vaults sealed by older versions.
const DEFAULT_KDF = { N: 1 << 16, r: 8, p: 1, dkLen: 32 };

function deriveKeyBytes (passphrase, salt, kdf) {
  return scrypt(new TextEncoder().encode(passphrase.normalize('NFKC')), salt, kdf);
}

async function aesKey (keyBytes, usages) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, usages);
}

/**
 * Encrypt a 64-char hex private key under a passphrase. Pure (no chrome) —
 * returns the storable vault blob.
 * @param {string} privateKeyHex - 64-char hex private key
 * @param {string} passphrase - user passphrase (>= 8 chars)
 * @param {object} [kdf] - scrypt cost override (tests use a cheap N)
 * @returns {Promise<object>} vault blob { v, kdf, N, r, p, salt, iv, ct }
 */
export async function encryptPrivateKey (privateKeyHex, passphrase, kdf = DEFAULT_KDF) {
  if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
    throw new Error('Private key must be 64-char hex');
  }
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE) {
    throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE} characters`);
  }

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await aesKey(deriveKeyBytes(passphrase, salt, kdf), ['encrypt']);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, hexToBytes(privateKeyHex))
  );

  return {
    v: 1,
    kdf: 'scrypt',
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ct: bytesToHex(ct)
  };
}

/**
 * Decrypt a vault blob with a passphrase. Pure (no chrome). A wrong passphrase
 * or any tampering fails the AES-GCM auth tag — surfaced as 'Incorrect
 * passphrase' so callers never distinguish wrong-key from corrupt-blob.
 * @param {object} blob - vault blob produced by encryptPrivateKey
 * @param {string} passphrase - user passphrase
 * @returns {Promise<string>} 64-char hex private key
 */
export async function decryptPrivateKey (blob, passphrase) {
  if (!blob || blob.v !== 1 || blob.kdf !== 'scrypt') {
    throw new Error('Unrecognised vault format');
  }

  const kdf = { N: blob.N, r: blob.r, p: blob.p, dkLen: 32 };
  const key = await aesKey(deriveKeyBytes(passphrase, hexToBytes(blob.salt), kdf), ['decrypt']);

  let pt;
  try {
    pt = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(blob.iv) }, key, hexToBytes(blob.ct))
    );
  } catch {
    throw new Error('Incorrect passphrase');
  }

  const hex = bytesToHex(pt);
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error('Incorrect passphrase');
  }
  return hex;
}

// ── chrome.storage.local wrappers ───────────────────────────────────────────

/**
 * Seal the private key into chrome.storage.local under the passphrase.
 * @param {string} privateKeyHex - 64-char hex private key
 * @param {string} passphrase - user passphrase (>= 8 chars)
 */
export async function createVault (privateKeyHex, passphrase) {
  const blob = await encryptPrivateKey(privateKeyHex, passphrase);
  await chrome.storage.local.set({ [VAULT_KEY]: blob });
}

/**
 * Read and decrypt the vault. Throws if no vault exists or the passphrase is
 * wrong.
 * @param {string} passphrase - user passphrase
 * @returns {Promise<string>} 64-char hex private key
 */
export async function unlockVault (passphrase) {
  const { [VAULT_KEY]: blob } = await chrome.storage.local.get([VAULT_KEY]);
  if (!blob) {
    throw new Error('No key vault found');
  }
  return decryptPrivateKey(blob, passphrase);
}

/**
 * Whether an encrypted vault is present on disk (independent of unlock state).
 * @returns {Promise<boolean>}
 */
export async function hasVault () {
  const { [VAULT_KEY]: blob } = await chrome.storage.local.get([VAULT_KEY]);
  return !!blob;
}

/**
 * Remove the encrypted vault from disk.
 * @returns {Promise<void>}
 */
export async function wipeVault () {
  await chrome.storage.local.remove([VAULT_KEY]);
}
