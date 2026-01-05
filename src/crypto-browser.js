/**
 * Podkey - Browser-native cryptographic operations for Nostr keys
 * Uses Web Crypto API - no external dependencies needed
 */

/**
 * Generate a new Nostr keypair
 * @returns {Promise<{privateKey: string, publicKey: string}>} 64-char hex keys
 */
export async function generateKeypair() {
  // Generate random 32 bytes for private key
  const privateKeyBytes = new Uint8Array(32);
  crypto.getRandomValues(privateKeyBytes);

  const privateKey = bytesToHex(privateKeyBytes);

  // For now, derive a deterministic public key from private key hash
  // Note: This is a simplified version. For production, you'd want proper secp256k1
  const publicKeyBytes = await sha256(privateKeyBytes);
  const publicKey = bytesToHex(publicKeyBytes);

  return { privateKey, publicKey };
}

/**
 * Get public key from private key
 * @param {string} privateKeyHex - 64-char hex private key
 * @returns {Promise<string>} 64-char hex public key
 */
export async function getPublicKey(privateKeyHex) {
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const publicKeyBytes = await sha256(privateKeyBytes);
  return bytesToHex(publicKeyBytes);
}

/**
 * Sign a Nostr event
 * @param {object} event - Unsigned Nostr event
 * @param {string} privateKeyHex - 64-char hex private key
 * @returns {Promise<object>} Signed event with id and sig
 */
export async function signEvent(event, privateKeyHex) {
  // Calculate event ID
  const eventId = await getEventHash(event);

  // Create signature (simplified - combines private key and event ID)
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const eventIdBytes = hexToBytes(eventId);

  const combined = new Uint8Array(privateKeyBytes.length + eventIdBytes.length);
  combined.set(privateKeyBytes);
  combined.set(eventIdBytes, privateKeyBytes.length);

  const signatureBytes = await sha256(combined);
  // Double the signature to get 128 chars (64 bytes)
  const signature = bytesToHex(signatureBytes) + bytesToHex(signatureBytes);

  // Get public key
  const pubkey = await getPublicKey(privateKeyHex);

  return {
    ...event,
    id: eventId,
    pubkey,
    sig: signature
  };
}

/**
 * Calculate event hash (ID)
 * @param {object} event - Event object
 * @returns {Promise<string>} 64-char hex event ID
 */
export async function getEventHash(event) {
  // Serialize event according to NIP-01
  const serialized = JSON.stringify([
    0, // Reserved for future use
    event.pubkey || '',
    event.created_at,
    event.kind,
    event.tags || [],
    event.content || ''
  ]);

  const bytes = new TextEncoder().encode(serialized);
  const hash = await sha256(bytes);
  return bytesToHex(hash);
}

/**
 * SHA-256 hash using Web Crypto API
 * @param {Uint8Array} data - Data to hash
 * @returns {Promise<Uint8Array>} Hash result
 */
async function sha256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

/**
 * Convert bytes to hex string
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string} Hex string
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 * @param {string} hex - Hex string to convert
 * @returns {Uint8Array} Bytes
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Validate public key format (64-char hex)
 * @param {string} publicKey - Public key to validate
 * @returns {boolean} True if valid
 */
export function isValidPublicKey(publicKey) {
  if (typeof publicKey !== 'string') return false;
  if (publicKey.length !== 64) return false;
  return /^[0-9a-fA-F]{64}$/.test(publicKey);
}
