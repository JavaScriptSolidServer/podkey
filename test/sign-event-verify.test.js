/**
 * Tests for the schnorr self-verification guard in signEvent (crypto.js).
 *
 * A key-holder must never emit a signature it cannot itself verify: a faulty
 * signing path (bad RNG, a library regression) producing a structurally-valid
 * but cryptographically-wrong signature has to throw, not return a bad token.
 *
 * The positive path is tested directly. The throw path is forced by patching
 * the shared @noble/secp256k1 schnorr.sign singleton (the same module instance
 * crypto.js imports) so it returns a corrupted signature — without touching src.
 */

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/secp256k1';
import { generateKeypair, signEvent, verifySignature, getEventHash } from '../src/crypto.js';

const baseEvent = () => ({ kind: 1, created_at: 1700000000, tags: [], content: 'self-verify' });

describe('signEvent self-verification', () => {
  const realSign = schnorr.sign;
  afterEach(() => { schnorr.sign = realSign; }); // always restore the singleton

  it('a correctly-signed event passes and round-trips through verifySignature', async () => {
    const kp = await generateKeypair();
    const signed = await signEvent(baseEvent(), kp.privateKey);

    assert.equal(signed.sig.length, 128);
    assert.equal(signed.pubkey, kp.publicKey);
    assert.equal(signed.id, getEventHash(signed), 'id must be the NIP-01 event hash');
    assert.equal(await verifySignature(signed), true);
  });

  it('throws when signing yields a signature that does not verify (flipped byte)', async () => {
    const kp = await generateKeypair();
    // Emit a 64-byte signature that is structurally valid but wrong: passes the
    // length check, fails schnorr.verify. The guard must catch it.
    schnorr.sign = (msg, sk) => {
      const sig = realSign(msg, sk);
      sig[0] ^= 0xff;
      return sig;
    };
    await assert.rejects(
      () => signEvent(baseEvent(), kp.privateKey),
      /Signature self-verification failed/
    );
  });

  it('throws when the signature is over the wrong message id', async () => {
    const kp = await generateKeypair();
    // Produce a real schnorr signature, but over a different 32-byte message
    // than the event id. It is a valid signature for *something* — just not for
    // this event — so length passes and self-verify against the true id fails.
    const wrongMsg = new Uint8Array(32).fill(7);
    schnorr.sign = (_msg, sk) => realSign(wrongMsg, sk);
    await assert.rejects(
      () => signEvent(baseEvent(), kp.privateKey),
      /Signature self-verification failed/
    );
  });

  it('does NOT leak the bad signature when it throws', async () => {
    const kp = await generateKeypair();
    let emitted;
    schnorr.sign = (msg, sk) => {
      const sig = realSign(msg, sk);
      sig[10] ^= 0x01;
      emitted = sig;
      return sig;
    };
    await assert.rejects(() => signEvent(baseEvent(), kp.privateKey));
    assert.ok(emitted, 'the patched signer ran');
    // The point of the guard: a bad signature is produced internally but never
    // returned to a caller. (The rejection above already proves no value is
    // returned; this asserts the failure happened *after* signing, at verify.)
  });
});

describe('verifySignature (guard primitive) rejects mutations', () => {
  it('rejects a mutated content (id no longer matches)', async () => {
    const kp = await generateKeypair();
    const signed = await signEvent(baseEvent(), kp.privateKey);
    const tampered = { ...signed, content: 'tampered' };
    // The signature is over the original id; verifying against the original id
    // still passes, but a consumer recomputing the id would reject it.
    assert.notEqual(getEventHash(tampered), signed.id, 'mutated content changes the id');
    assert.equal(await verifySignature({ ...tampered, id: getEventHash(tampered) }), false);
  });

  it('rejects a flipped signature byte', async () => {
    const kp = await generateKeypair();
    const signed = await signEvent(baseEvent(), kp.privateKey);
    const badSig = (parseInt(signed.sig[0], 16) ^ 0x8).toString(16) + signed.sig.slice(1);
    assert.equal(await verifySignature({ ...signed, sig: badSig }), false);
  });

  it('rejects a signature verified against a different pubkey', async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const signed = await signEvent(baseEvent(), kp.privateKey);
    assert.equal(await verifySignature({ ...signed, pubkey: other.publicKey }), false);
  });
});
