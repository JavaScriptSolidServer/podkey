import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hexToNsec, nsecToHex, normalizeSecretKeyToHex } from '../src/keyformat.js';

// Canonical NIP-19 spec test vector.
const NSEC = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5';
const HEX = '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa';
const NPUB = 'npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg';

test('nsecToHex decodes the NIP-19 spec vector', () => {
  assert.equal(nsecToHex(NSEC), HEX);
});

test('normalizeSecretKeyToHex converts nsec -> hex inline', () => {
  assert.equal(normalizeSecretKeyToHex(NSEC), HEX);
});

test('normalizeSecretKeyToHex passes hex through, lowercased', () => {
  assert.equal(normalizeSecretKeyToHex(HEX), HEX);
  assert.equal(normalizeSecretKeyToHex(HEX.toUpperCase()), HEX);
});

test('normalizeSecretKeyToHex trims surrounding whitespace/newlines', () => {
  assert.equal(normalizeSecretKeyToHex(`  ${NSEC}\n`), HEX);
  assert.equal(normalizeSecretKeyToHex(`\t${HEX} `), HEX);
});

test('uppercase nsec is accepted (bech32 is case-insensitive, not mixed)', () => {
  assert.equal(normalizeSecretKeyToHex(NSEC.toUpperCase()), HEX);
});

test('rejects an npub (wrong human-readable part)', () => {
  assert.throws(() => normalizeSecretKeyToHex(NPUB), /Invalid key/);
});

test('rejects a corrupted nsec (bad checksum)', () => {
  const corrupted = NSEC.slice(0, -1) + (NSEC.endsWith('a') ? 'q' : 'a');
  assert.throws(() => nsecToHex(corrupted), /Invalid key/);
});

test('rejects mixed-case bech32', () => {
  const mixed = NSEC.slice(0, 10).toUpperCase() + NSEC.slice(10);
  assert.throws(() => normalizeSecretKeyToHex(mixed), /Invalid key/);
});

test('rejects short hex, long hex, and non-hex junk', () => {
  assert.throws(() => normalizeSecretKeyToHex(HEX.slice(0, 63)), /Invalid key/);
  assert.throws(() => normalizeSecretKeyToHex(HEX + 'ab'), /Invalid key/);
  assert.throws(() => normalizeSecretKeyToHex('not a key'), /Invalid key/);
  assert.throws(() => normalizeSecretKeyToHex(''), /Invalid key/);
});

test('rejects non-string input', () => {
  assert.throws(() => normalizeSecretKeyToHex(null), /Invalid key/);
  assert.throws(() => normalizeSecretKeyToHex(undefined), /Invalid key/);
});

test('hexToNsec encodes the NIP-19 spec vector', () => {
  assert.equal(hexToNsec(HEX), NSEC);
});

test('hexToNsec accepts uppercase hex and round-trips through nsecToHex', () => {
  assert.equal(nsecToHex(hexToNsec(HEX.toUpperCase())), HEX);
});

test('hexToNsec rejects non-hex and wrong-length input', () => {
  assert.throws(() => hexToNsec(HEX.slice(0, 63)), /Invalid key/);
  assert.throws(() => hexToNsec(HEX + '00'), /Invalid key/);
  assert.throws(() => hexToNsec('zz' + HEX.slice(2)), /Invalid key/);
  assert.throws(() => hexToNsec(null), /Invalid key/);
});
