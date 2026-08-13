import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { getPublicKey } from './crypto.js';

export const PASSKEY_CONFIG_KEY = 'podkey_passkey';

// HKDF domain separation. The derive path (a Nostr identity computed from the
// PRF output — the cross-implementation KDF contract other Podkey-compatible
// clients must match byte-for-byte) and the wrap path (an AES key that merely
// encrypts an existing identity) use distinct info strings so the two can
// never yield the same bytes, whatever the salts.
const DERIVE_INFO = new TextEncoder().encode('podkey/nostr-secret/v1');
const WRAP_INFO = new TextEncoder().encode('podkey/wrap/v1');

export function toBase64Url (bytes) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function fromBase64Url (value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(base64);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function hkdf (secret, salt, info) {
  const key = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info }, key, 256
  ));
}

export async function deriveNostrKey (prfOutput, derivationSalt) {
  for (let counter = 0; counter < 256; counter++) {
    const info = new Uint8Array(DERIVE_INFO.length + 1);
    info.set(DERIVE_INFO);
    info[DERIVE_INFO.length] = counter;
    const candidate = bytesToHex(await hkdf(prfOutput, derivationSalt, info));
    try {
      getPublicKey(candidate);
      return candidate;
    } catch {
      // The negligible invalid-scalar case deterministically advances counter.
    }
  }
  throw new Error('Could not derive a valid Nostr key');
}

export async function wrapPrivateKey (privateKeyHex, prfOutput) {
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const wrappingBytes = await hkdf(prfOutput, salt, WRAP_INFO);
  const key = await crypto.subtle.importKey('raw', wrappingBytes, 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, hexToBytes(privateKeyHex));
  return { salt: toBase64Url(salt), iv: toBase64Url(iv), ct: toBase64Url(ct) };
}

export async function unwrapPrivateKey (wrapped, prfOutput) {
  try {
    const wrappingBytes = await hkdf(prfOutput, fromBase64Url(wrapped.salt), WRAP_INFO);
    const key = await crypto.subtle.importKey('raw', wrappingBytes, 'AES-GCM', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64Url(wrapped.iv) }, key, fromBase64Url(wrapped.ct)
    );
    return bytesToHex(new Uint8Array(plaintext));
  } catch {
    throw new Error('Passkey could not unlock this identity');
  }
}

export function newPasskeySalt () {
  return randomBytes(32);
}

// rp.id is deliberately omitted below, so Chrome binds the credential to the
// extension origin (chrome-extension://<id>). The extension ID therefore IS
// part of the identity: an unpacked/dev install has a different ID than the
// Web Store build and cannot resolve credentials created under the other. Dev
// installs that need passkey parity must pin the ID via a manifest `key`.
//
// The PRF extension is requested at creation so the authenticator provisions
// it, but the creation-time PRF output is never used for key material: some
// authenticators return a different value at create() than at get(), and
// every future unlock uses get(). Callers obtain key material exclusively via
// getPasskeyPrf, so a value baked in at setup is always reproducible at unlock.
export async function createPasskey (prfSalt, label = 'Podkey identity') {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('Passkeys are not supported by this browser');
  }
  const credential = await navigator.credentials.create({ publicKey: {
    challenge: randomBytes(32),
    user: { id: randomBytes(32), name: 'podkey', displayName: label },
    rp: { name: 'Podkey' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    timeout: 120000,
    attestation: 'none',
    extensions: { prf: { eval: { first: prfSalt } } }
  } });
  if (!credential) throw new Error('Passkey creation was cancelled');
  return { credentialId: toBase64Url(new Uint8Array(credential.rawId)) };
}

export async function getPasskeyPrf (credentialId, prfSalt) {
  const id = typeof credentialId === 'string' ? fromBase64Url(credentialId) : credentialId;
  const assertion = await navigator.credentials.get({ publicKey: {
    challenge: randomBytes(32),
    allowCredentials: [{ type: 'public-key', id }],
    userVerification: 'required',
    timeout: 120000,
    extensions: { prf: { eval: { first: prfSalt } } }
  } });
  const output = assertion?.getClientExtensionResults().prf?.results?.first;
  if (!output) throw new Error('This passkey does not support secure key derivation (PRF)');
  return new Uint8Array(output);
}
