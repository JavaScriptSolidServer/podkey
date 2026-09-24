// Key-path signing for a chain's transactions. The sighash follows the parent's family (SPEC 3):
// beside a BLAKE2b parent the kernel's params carry `unifiedSighashParam` and the unified sighash
// is the rule; beside stock Bitcoin it is BIP 341's. Browsers and Node alike; no imports.
export const SIGHASH_UNIFIED = 0x20;
export const usesUnifiedSighash = (k) => k?.params?.unifiedSighashParam != null;
// the message an input's key-path signature commits to, and the hash type byte appended to it
export function keyPathSighash({ k, hash }, tx, i, prevouts) {
  const unified = usesUnifiedSighash(k); const ht = 0x01 | (unified ? SIGHASH_UNIFIED : 0);
  let m = unified ? k.interpreter.sighashUnified(tx, i, prevouts, ht, 2) : k.interpreter.sighashTaproot(tx, i, prevouts, ht);
  if (typeof m === 'string') m = hash.hexToBytes(m); return { m, ht };
}
// sign every input of `tx` (all key-path spends of `key`) in place; returns tx
export function signKeyPath({ k, hash, signer }, tx, prevouts, key) {
  tx.witness = tx.inputs.map((_, i) => { const { m, ht } = keyPathSighash({ k, hash }, tx, i, prevouts); return [hash.bytesToHex(signer.schnorrSign(m, key)) + ht.toString(16).padStart(2, '0')]; });
  return tx;
}
// our own check before publishing: every witness is a valid signature by `pub` under the chain's sighash
export function verifyKeyPath({ k, hash, secp }, tx, prevouts, pub) {
  return tx.inputs.every((_, i) => { const { m, ht } = keyPathSighash({ k, hash }, tx, i, prevouts); const w = tx.witness?.[i]?.[0] ?? ''; return w.length === 130 && w.endsWith(ht.toString(16).padStart(2, '0')) && secp.verifySchnorr(m, hash.hexToBytes(w.slice(0, 128)), hash.hexToBytes(pub)); });
}
