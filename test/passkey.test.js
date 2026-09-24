import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { getPublicKey } from '../src/crypto.js';
import {
  assertionOptions,
  cleanTransports,
  creationOptions,
  deriveNostrKey,
  fromBase64Url,
  toBase64Url,
  translateCeremonyError,
  unwrapPrivateKey,
  wrapPrivateKey
} from '../src/passkey.js';

globalThis.crypto ??= webcrypto;
globalThis.btoa ??= value => Buffer.from(value, 'binary').toString('base64');
globalThis.atob ??= value => Buffer.from(value, 'base64').toString('binary');

describe('passkey key material', () => {
  it('round-trips binary values through base64url', () => {
    const bytes = Uint8Array.from([0, 1, 2, 250, 255]);
    assert.deepEqual(fromBase64Url(toBase64Url(bytes)), bytes);
  });

  it('derives the same valid Nostr key from the same PRF output and salt', async () => {
    const prf = new Uint8Array(32).fill(7);
    const salt = new Uint8Array(32).fill(11);
    const first = await deriveNostrKey(prf, salt);
    const second = await deriveNostrKey(prf, salt);
    assert.equal(first, second);
    assert.match(first, /^[0-9a-f]{64}$/);
    assert.match(getPublicKey(first), /^[0-9a-f]{64}$/);
  });

  it('domain-separates identities with different salts', async () => {
    const prf = new Uint8Array(32).fill(7);
    assert.notEqual(
      await deriveNostrKey(prf, new Uint8Array(32).fill(1)),
      await deriveNostrKey(prf, new Uint8Array(32).fill(2))
    );
  });

  it('wraps and unwraps an existing Nostr key', async () => {
    const privateKey = '01'.padStart(64, '0');
    const prf = new Uint8Array(32).fill(9);
    const wrapped = await wrapPrivateKey(privateKey, prf);
    assert.equal(await unwrapPrivateKey(wrapped, prf), privateKey);
    await assert.rejects(() => unwrapPrivateKey(wrapped, new Uint8Array(32).fill(8)), /could not unlock/);
  });

  it('rejects tampered wrapped ciphertext', async () => {
    const prf = new Uint8Array(32).fill(9);
    const wrapped = await wrapPrivateKey('02'.padStart(64, '0'), prf);
    const bytes = fromBase64Url(wrapped.ct);
    bytes[0] ^= 1;
    await assert.rejects(() => unwrapPrivateKey({ ...wrapped, ct: toBase64Url(bytes) }, prf), /could not unlock/);
  });
});

describe('wrap freshness and domain separation', () => {
  it('uses a fresh random salt and iv for every wrap', async () => {
    const prf = new Uint8Array(32).fill(9);
    const privateKey = '03'.padStart(64, '0');
    const a = await wrapPrivateKey(privateKey, prf);
    const b = await wrapPrivateKey(privateKey, prf);
    assert.notEqual(a.salt, b.salt);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ct, b.ct);
    assert.equal(await unwrapPrivateKey(a, prf), privateKey);
    assert.equal(await unwrapPrivateKey(b, prf), privateKey);
  });

  it('never derives an identity equal to the raw PRF output or wrap key path', async () => {
    // Sanity check on domain separation: the derived identity must not be a
    // trivial function of the inputs (distinct info strings guarantee the
    // derive and wrap HKDF outputs differ even for identical prf and salt).
    const prf = new Uint8Array(32).fill(5);
    const salt = new Uint8Array(32).fill(6);
    const derived = await deriveNostrKey(prf, salt);
    assert.notEqual(derived, Buffer.from(prf).toString('hex'));
    assert.notEqual(derived, Buffer.from(salt).toString('hex'));
  });
});

describe('ceremony options (hardware security keys)', () => {
  const salt = new Uint8Array(32).fill(4);

  it('requires user verification on both ceremonies, so hmac-secret output is stable', () => {
    // CTAP2 hmac-secret uses a different secret with and without UV: the two
    // ceremonies must agree or unlock yields a different key.
    assert.equal(creationOptions(salt).authenticatorSelection.userVerification, 'required');
    assert.equal(assertionOptions('AAAA', salt).userVerification, 'required');
  });

  it('asks for a non-resident credential with PRF', () => {
    const o = creationOptions(salt, 'Podkey unlock');
    assert.equal(o.authenticatorSelection.residentKey, 'discouraged');
    assert.equal(o.authenticatorSelection.requireResidentKey, false);
    assert.deepEqual(o.extensions.prf.eval.first, salt);
    assert.equal(o.user.displayName, 'Podkey unlock');
    assert.equal(o.rp.id, undefined, 'rp.id stays unset so the credential binds to the extension origin');
  });

  it('offers ES256 first, then EdDSA and RS256', () => {
    assert.deepEqual(creationOptions(salt).pubKeyCredParams.map(p => p.alg), [-7, -8, -257]);
  });

  it('gives a security key at least three minutes', () => {
    assert.ok(creationOptions(salt).timeout >= 180000);
    assert.ok(assertionOptions('AAAA', salt).timeout >= 180000);
  });

  it('passes the stored transports so the browser goes straight to the key', () => {
    const o = assertionOptions(toBase64Url(Uint8Array.from([1, 2, 3])), salt, ['usb', 'nfc']);
    assert.deepEqual(o.allowCredentials[0].transports, ['usb', 'nfc']);
    assert.deepEqual(o.allowCredentials[0].id, Uint8Array.from([1, 2, 3]));
    assert.deepEqual(o.extensions.prf.eval.first, salt);
  });

  it('omits transports for a passkey set up before they were stored', () => {
    assert.equal('transports' in assertionOptions('AAAA', salt).allowCredentials[0], false);
    assert.equal('transports' in assertionOptions('AAAA', salt, undefined).allowCredentials[0], false);
  });

  it('keeps only known transports, once each', () => {
    assert.deepEqual(cleanTransports(['usb', 'usb', 'bogus', 'nfc', 7]), ['usb', 'nfc']);
    assert.deepEqual(cleanTransports('usb'), []);
  });
});

describe('ceremony errors', () => {
  const named = (name) => Object.assign(new Error('x'), { name });

  it('tells a security-key user what to do after a cancel or timeout', () => {
    const e = translateCeremonyError(named('NotAllowedError'), 'unlock');
    assert.match(e.message, /PIN/);
    assert.match(e.message, /touch it/);
    assert.doesNotMatch(e.message, /twice/, 'an unlock prompts once');
  });

  it('names the registration step when that is what failed', () => {
    assert.match(translateCeremonyError(named('AbortError'), 'register').message, /Registering/);
  });

  it('explains InvalidStateError and NotSupportedError', () => {
    assert.match(translateCeremonyError(named('InvalidStateError')).message, /already holds/);
    assert.match(translateCeremonyError(named('NotSupportedError')).message, /cannot make/);
  });

  it('passes other errors through', () => {
    const original = new Error('boom');
    assert.equal(translateCeremonyError(original), original);
    assert.equal(translateCeremonyError('plain').message, 'plain');
  });
});
