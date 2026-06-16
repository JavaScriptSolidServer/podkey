/**
 * Tests for the encrypted-at-rest key vault crypto core (src/vault.js).
 *
 * Only the pure functions (encryptPrivateKey / decryptPrivateKey) are exercised
 * here — they have no chrome.storage dependency. A cheap scrypt cost (N=256) is
 * used so the suite stays fast; the cost parameters are sealed into the blob, so
 * decrypt re-derives with the same params regardless of the production default.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encryptPrivateKey, decryptPrivateKey } from '../src/vault.js';

const CHEAP_KDF = { N: 256, r: 8, p: 1, dkLen: 32 };
const PRIVKEY = '1f2e3d4c5b6a798800112233445566778899aabbccddeeff0011223344556677';
const PASS = 'correct horse battery staple';

test('round-trips a private key through encrypt -> decrypt', async () => {
  const blob = await encryptPrivateKey(PRIVKEY, PASS, CHEAP_KDF);
  const out = await decryptPrivateKey(blob, PASS);
  assert.equal(out, PRIVKEY);
});

test('blob has the expected shape and sealed KDF params', async () => {
  const blob = await encryptPrivateKey(PRIVKEY, PASS, CHEAP_KDF);
  assert.equal(blob.v, 1);
  assert.equal(blob.kdf, 'scrypt');
  assert.equal(blob.N, CHEAP_KDF.N);
  assert.match(blob.salt, /^[0-9a-f]{32}$/); // 16 bytes
  assert.match(blob.iv, /^[0-9a-f]{24}$/);   // 12 bytes
  assert.match(blob.ct, /^[0-9a-f]+$/);
  assert.ok(!blob.ct.includes(PRIVKEY), 'ciphertext must not contain the plaintext key');
});

test('wrong passphrase fails closed with a generic error', async () => {
  const blob = await encryptPrivateKey(PRIVKEY, PASS, CHEAP_KDF);
  await assert.rejects(() => decryptPrivateKey(blob, 'wrong passphrase!!'), /Incorrect passphrase/);
});

test('tampered ciphertext fails the GCM auth tag', async () => {
  const blob = await encryptPrivateKey(PRIVKEY, PASS, CHEAP_KDF);
  // Flip the last ciphertext byte.
  const last = blob.ct.slice(-2);
  const flipped = (parseInt(last, 16) ^ 0xff).toString(16).padStart(2, '0');
  const tampered = { ...blob, ct: blob.ct.slice(0, -2) + flipped };
  await assert.rejects(() => decryptPrivateKey(tampered, PASS), /Incorrect passphrase/);
});

test('rejects a passphrase shorter than 8 characters', async () => {
  await assert.rejects(() => encryptPrivateKey(PRIVKEY, 'short', CHEAP_KDF), /at least 8/);
});

test('rejects a non-hex / wrong-length private key', async () => {
  await assert.rejects(() => encryptPrivateKey('not-hex', PASS, CHEAP_KDF), /64-char hex/);
  await assert.rejects(() => encryptPrivateKey('abcd', PASS, CHEAP_KDF), /64-char hex/);
});

test('uses a fresh salt and iv per encryption (no reuse)', async () => {
  const a = await encryptPrivateKey(PRIVKEY, PASS, CHEAP_KDF);
  const b = await encryptPrivateKey(PRIVKEY, PASS, CHEAP_KDF);
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ct, b.ct);
});

test('rejects an unrecognised vault format', async () => {
  await assert.rejects(() => decryptPrivateKey({ v: 99 }, PASS), /Unrecognised vault format/);
});
