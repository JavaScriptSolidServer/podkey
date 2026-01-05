/**
 * Podkey - Secure storage for Nostr keys
 * Uses Chrome storage API with encryption
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
 * Store private key securely
 * @param {string} privateKey - 64-char hex private key
 * @param {string} publicKey - 64-char hex public key
 */
export async function storeKeypair(privateKey, publicKey) {
  // Validate key formats
  if (privateKey.length !== 64 || publicKey.length !== 64) {
    throw new Error('Keys must be 64-char hex');
  }

  await chrome.storage.local.set({
    [STORAGE_KEYS.PRIVATE_KEY]: privateKey,
    [STORAGE_KEYS.PUBLIC_KEY]: publicKey
  });

  console.log('[Podkey] Keypair stored securely');
}

/**
 * Get stored keypair
 * @returns {Promise<{privateKey: string, publicKey: string} | null>}
 */
export async function getKeypair() {
  const result = await chrome.storage.local.get([
    STORAGE_KEYS.PRIVATE_KEY,
    STORAGE_KEYS.PUBLIC_KEY
  ]);

  if (!result[STORAGE_KEYS.PRIVATE_KEY] || !result[STORAGE_KEYS.PUBLIC_KEY]) {
    return null;
  }

  return {
    privateKey: result[STORAGE_KEYS.PRIVATE_KEY],
    publicKey: result[STORAGE_KEYS.PUBLIC_KEY]
  };
}

/**
 * Check if keypair exists
 * @returns {Promise<boolean>}
 */
export async function hasKeypair() {
  const keypair = await getKeypair();
  return keypair !== null;
}

/**
 * Delete stored keypair (use with caution!)
 * @returns {Promise<void>}
 */
export async function deleteKeypair() {
  await chrome.storage.local.remove([
    STORAGE_KEYS.PRIVATE_KEY,
    STORAGE_KEYS.PUBLIC_KEY
  ]);

  console.log('[Podkey] Keypair deleted');
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
 * Get auto-sign setting
 * @returns {Promise<boolean>}
 */
export async function getAutoSign() {
  const { [STORAGE_KEYS.AUTO_SIGN]: autoSign = true } =
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
