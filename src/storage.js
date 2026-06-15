/**
 * Podkey - Secure storage for Nostr keys
 *
 * Private keys are stored in chrome.storage.session (in-memory only, never
 * persisted to disk, cleared when the service worker terminates).
 *
 * Public keys remain in chrome.storage.local so the popup can display the
 * user's pubkey/DID without requiring the private key to be unlocked.
 */

const STORAGE_KEYS = {
  PRIVATE_KEY: 'podkey_private_key',
  PUBLIC_KEY: 'podkey_public_key',
  TRUSTED_ORIGINS: 'podkey_trusted_origins',
  AUTO_SIGN: 'podkey_auto_sign',
  PROFILES: 'podkey_profiles',
  CURRENT_PROFILE: 'podkey_current_profile'
};

/**
 * Store keypair securely.
 * Private key goes to session storage (in-memory only).
 * Public key goes to local storage (persisted, but not secret).
 * @param {string} privateKey - 64-char hex private key
 * @param {string} publicKey - 64-char hex public key
 */
export async function storeKeypair(privateKey, publicKey) {
  // Validate key formats
  if (privateKey.length !== 64 || publicKey.length !== 64) {
    throw new Error('Keys must be 64-char hex');
  }

  // Private key: session storage only (in-memory, never written to disk)
  await chrome.storage.session.set({
    [STORAGE_KEYS.PRIVATE_KEY]: privateKey
  });

  // Public key: local storage (needs to survive service worker restarts
  // so the popup can show the user's identity without the private key)
  await chrome.storage.local.set({
    [STORAGE_KEYS.PUBLIC_KEY]: publicKey
  });

  // Remove any legacy private key from local storage left by older versions
  await chrome.storage.local.remove([STORAGE_KEYS.PRIVATE_KEY]);

  console.log('[Podkey] Keypair stored (private key in session storage only)');
}

/**
 * Get stored keypair.
 * Private key comes from session storage, public key from local storage.
 * Returns null if either key is missing (e.g. service worker restarted and
 * session storage was cleared -- user will need to re-import).
 * @returns {Promise<{privateKey: string, publicKey: string} | null>}
 */
export async function getKeypair() {
  const { [STORAGE_KEYS.PRIVATE_KEY]: privateKey } =
    await chrome.storage.session.get([STORAGE_KEYS.PRIVATE_KEY]);

  const { [STORAGE_KEYS.PUBLIC_KEY]: publicKey } =
    await chrome.storage.local.get([STORAGE_KEYS.PUBLIC_KEY]);

  if (!privateKey || !publicKey) {
    return null;
  }

  return { privateKey, publicKey };
}

/**
 * Check if a usable keypair exists (private key in session + public key on disk).
 * @returns {Promise<boolean>}
 */
export async function hasKeypair() {
  const keypair = await getKeypair();
  return keypair !== null;
}

/**
 * Check if a public key exists on disk (may not have a private key in session).
 * Useful for the popup to show identity even when the session has expired.
 * @returns {Promise<string|null>} The public key hex, or null
 */
export async function getStoredPublicKey() {
  const { [STORAGE_KEYS.PUBLIC_KEY]: publicKey } =
    await chrome.storage.local.get([STORAGE_KEYS.PUBLIC_KEY]);
  return publicKey || null;
}

/**
 * Delete stored keypair from both session and local storage.
 * @returns {Promise<void>}
 */
export async function deleteKeypair() {
  await chrome.storage.session.remove([STORAGE_KEYS.PRIVATE_KEY]);
  await chrome.storage.local.remove([
    STORAGE_KEYS.PRIVATE_KEY, // clean up any legacy local copy
    STORAGE_KEYS.PUBLIC_KEY
  ]);

  console.log('[Podkey] Keypair deleted from all storage');
}

/**
 * Add a trusted origin
 * @param {string} origin - Origin to trust (e.g., https://example.com)
 */
export async function addTrustedOrigin(origin) {
  const { [STORAGE_KEYS.TRUSTED_ORIGINS]: trusted = {} } =
    await chrome.storage.local.get([STORAGE_KEYS.TRUSTED_ORIGINS]);

  trusted[origin] = {
    addedAt: Date.now(),
    lastUsed: Date.now()
  };

  await chrome.storage.local.set({
    [STORAGE_KEYS.TRUSTED_ORIGINS]: trusted
  });
}

/**
 * Remove a trusted origin
 * @param {string} origin - Origin to untrust
 */
export async function removeTrustedOrigin(origin) {
  const { [STORAGE_KEYS.TRUSTED_ORIGINS]: trusted = {} } =
    await chrome.storage.local.get([STORAGE_KEYS.TRUSTED_ORIGINS]);

  delete trusted[origin];

  await chrome.storage.local.set({
    [STORAGE_KEYS.TRUSTED_ORIGINS]: trusted
  });
}

/**
 * Check if origin is trusted
 * @param {string} origin - Origin to check
 * @returns {Promise<boolean>}
 */
export async function isTrustedOrigin(origin) {
  const { [STORAGE_KEYS.TRUSTED_ORIGINS]: trusted = {} } =
    await chrome.storage.local.get([STORAGE_KEYS.TRUSTED_ORIGINS]);

  return trusted[origin] !== undefined;
}

/**
 * Get all trusted origins
 * @returns {Promise<Object>} Map of origin -> metadata
 */
export async function getTrustedOrigins() {
  const { [STORAGE_KEYS.TRUSTED_ORIGINS]: trusted = {} } =
    await chrome.storage.local.get([STORAGE_KEYS.TRUSTED_ORIGINS]);

  return trusted;
}

/**
 * Get auto-sign setting.
 * Defaults to OFF: a freshly installed extension must not silently sign or
 * auto-trust any origin (including recognised Solid hosts) until the user
 * deliberately enables auto-sign from the popup. This keeps the silent
 * trusted-origin Solid / NIP-98 path strictly opt-in.
 * @returns {Promise<boolean>}
 */
export async function getAutoSign() {
  const { [STORAGE_KEYS.AUTO_SIGN]: autoSign = false } =
    await chrome.storage.local.get([STORAGE_KEYS.AUTO_SIGN]);

  return autoSign;
}

/**
 * Set auto-sign setting
 * @param {boolean} enabled - Enable or disable auto-sign
 */
export async function setAutoSign(enabled) {
  await chrome.storage.local.set({
    [STORAGE_KEYS.AUTO_SIGN]: enabled
  });
}
