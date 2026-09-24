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
const PRF_UNSUPPORTED_MESSAGE =
  'This authenticator completed sign-in but did not return a derivation secret ' +
  '(the WebAuthn PRF / hmac-secret extension). Podkey needs PRF to derive your key. ' +
  'Try a phone passkey or a modern security key that supports PRF, or create a ' +
  'passphrase-based key instead.';

// Transports an authenticator can report (WebAuthn AuthenticatorTransport).
// Passing the ones a credential reported back in allowCredentials lets the
// browser go straight to "insert and touch your security key" (or NFC)
// instead of opening its generic chooser, which on desktop leads with the
// phone/QR option — where hardware-key users got lost.
export const KNOWN_TRANSPORTS = ['usb', 'nfc', 'ble', 'hybrid', 'internal', 'smart-card'];

export function cleanTransports (transports) {
  if (!Array.isArray(transports)) return [];
  return [...new Set(transports.filter(t => KNOWN_TRANSPORTS.includes(t)))];
}

// WebAuthn surfaces almost every ceremony failure as NotAllowedError — a
// deliberately vague catch-all covering user cancel, timeout, no available
// authenticator, a wrong PIN, and the document not having focus. Name the
// likely causes for the step that failed without over-claiming which one
// occurred; pass any other error through unchanged.
export function translateCeremonyError (err, step = 'unlock') {
  const name = err?.name;
  if (name === 'NotAllowedError' || name === 'AbortError') {
    const what = step === 'register'
      ? 'Registering the passkey was cancelled or timed out.'
      : 'The passkey step was cancelled or timed out.';
    return new Error(
      `${what} With a security key: insert it, enter its PIN if asked, and touch it when it flashes. ` +
      'Keep this window in front while you do, then try again.'
    );
  }
  if (name === 'InvalidStateError') {
    return new Error('This authenticator already holds a Podkey passkey. Use it to unlock, or choose a different key.');
  }
  if (name === 'NotSupportedError') {
    return new Error('This authenticator cannot make the kind of passkey Podkey needs. Try a phone passkey or a newer security key.');
  }
  if (name === 'SecurityError') {
    return new Error('The browser refused the passkey request for this extension. Reload Podkey and try again.');
  }
  return err instanceof Error ? err : new Error(String(err?.message || err));
}

// userVerification is 'required' on both ceremonies, and must stay equal
// between them: CTAP2 hmac-secret derives from a different per-credential
// secret with and without user verification, so a key registered with UV but
// asserted without it (or the reverse) returns a different PRF output — a
// different Nostr identity, or an unwrap failure. For a security key, UV is
// its PIN; the browser asks the person to set one if the key has none.
export function creationOptions (prfSalt, label = 'Podkey identity') {
  return {
    challenge: randomBytes(32),
    user: { id: randomBytes(32), name: 'podkey', displayName: label },
    rp: { name: 'Podkey' },
    // ES256 first (every FIDO2 key), then EdDSA and RS256 so an authenticator
    // that offers only those (some Windows Hello TPMs: RS256) is not refused.
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -257 }
    ],
    // Podkey stores the credentialId itself and always passes it via
    // allowCredentials at unlock, so it never needs a discoverable (resident)
    // credential. Requesting one adds cost, uses one of a security key's few
    // resident slots and, on some TPM/security-key authenticators (e.g.
    // tpm-fido), a makeCredential failure path — so discourage it.
    // hmac-secret/PRF works fine on non-resident credentials.
    authenticatorSelection: { residentKey: 'discouraged', requireResidentKey: false, userVerification: 'required' },
    // Three minutes: long enough to find a key, set a first PIN and touch it.
    timeout: 180000,
    attestation: 'none',
    extensions: { prf: { eval: { first: prfSalt } } }
  };
}

export function assertionOptions (credentialId, prfSalt, transports = []) {
  const id = typeof credentialId === 'string' ? fromBase64Url(credentialId) : credentialId;
  const hint = cleanTransports(transports);
  return {
    challenge: randomBytes(32),
    allowCredentials: [{ type: 'public-key', id, ...(hint.length ? { transports: hint } : {}) }],
    userVerification: 'required',
    timeout: 180000,
    extensions: { prf: { eval: { first: prfSalt } } }
  };
}

function requireWebAuthn () {
  if (!globalThis.PublicKeyCredential || !globalThis.navigator?.credentials) {
    throw new Error('Passkeys are not supported by this browser');
  }
}

export async function createPasskey (prfSalt, label = 'Podkey identity') {
  requireWebAuthn();
  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey: creationOptions(prfSalt, label) });
  } catch (err) {
    throw translateCeremonyError(err, 'register');
  }
  if (!credential) throw new Error('Passkey creation was cancelled');
  // Definitive PRF-support signal: with prf requested at creation, the client
  // reports whether the authenticator provisioned hmac-secret. If it didn't,
  // every unlock's get() would fail to return key material — so stop here with
  // an actionable message instead of persisting a credential that can't unlock.
  const prf = credential.getClientExtensionResults?.().prf;
  if (!prf || prf.enabled !== true) {
    throw new Error(PRF_UNSUPPORTED_MESSAGE);
  }
  let transports = [];
  try { transports = cleanTransports(credential.response?.getTransports?.()); } catch { /* only a hint */ }
  return { credentialId: toBase64Url(new Uint8Array(credential.rawId)), transports };
}

export async function getPasskeyPrf (credentialId, prfSalt, transports = []) {
  requireWebAuthn();
  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: assertionOptions(credentialId, prfSalt, transports) });
  } catch (err) {
    throw translateCeremonyError(err, 'unlock');
  }
  const output = assertion?.getClientExtensionResults().prf?.results?.first;
  if (!output) throw new Error(PRF_UNSUPPORTED_MESSAGE);
  return new Uint8Array(output);
}
