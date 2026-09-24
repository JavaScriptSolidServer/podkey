// Blocks on a sidestr chain (SPEC 4): building, the block data that is signed, the virtual
// transactions the challenge is evaluated against, the solution's place in the coinbase.
const SIGNET_HEADER = 'ecc7daa2';
const NULL32 = '00'.repeat(32);

const compactSize = (n) => n < 0xfd ? [n] : n <= 0xffff ? [0xfd, n & 0xff, n >> 8] : [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff];
const readCompact = (b, i) => b[i] < 0xfd ? [b[i], i + 1] : b[i] === 0xfd ? [b[i + 1] | (b[i + 2] << 8), i + 3] : [b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] * 2 ** 24), i + 5];
const hex = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

// serialized script witness: count, then each item length-prefixed
export function encodeWitness(items) { const out = [...compactSize(items.length)]; for (const it of items) { const b = unhex(it); out.push(...compactSize(b.length), ...b); } return hex(Uint8Array.from(out)); }
export function decodeWitness(h) { const b = unhex(h); let [n, i] = readCompact(b, 0); const items = []; while (n-- > 0) { let len; [len, i] = readCompact(b, i); items.push(hex(b.slice(i, i + len))); i += len; } return items; }

// the coinbase output carrying the witness commitment, and the solution push after it
export function commitmentOutput(block) {
  const cb = block.transactions[0]; if (!cb) return null;
  for (let i = cb.outputs.length - 1; i >= 0; i--) { const spk = cb.outputs[i].scriptPubKey; if (spk.startsWith('6a24aa21a9ed') && spk.length >= 76) return { index: i, spk }; }
  return null;
}
export function solutionOf(block) {
  const c = commitmentOutput(block); if (!c) return null;
  const rest = unhex(c.spk.slice(76)); if (!rest.length) return null;
  // one push: direct (<= 75 bytes), OP_PUSHDATA1 (<= 255) or OP_PUSHDATA2 (<= 65535) as the size needs (SPEC 4)
  let n, at; if (rest[0] > 0 && rest[0] <= 75) { n = rest[0]; at = 1; } else if (rest[0] === 0x4c && rest.length >= 2) { n = rest[1]; at = 2; } else if (rest[0] === 0x4d && rest.length >= 3) { n = rest[1] | (rest[2] << 8); at = 3; } else return null;
  if (n === 0 || rest.length !== at + n) return null;
  const push = hex(rest.slice(at, at + n)); if (!push.startsWith(SIGNET_HEADER)) return null;
  return { witness: decodeWitness(push.slice(8)), stripped: c.spk.slice(0, 76), index: c.index };
}
export function withSolution(block, witnessItems) {
  const c = commitmentOutput(block); if (!c) throw new Error('no witness commitment output to carry the solution');
  const push = SIGNET_HEADER + encodeWitness(witnessItems); const len = push.length / 2; if (len > 65535) throw new Error('solution too long for one push');
  const op = len <= 75 ? len.toString(16).padStart(2, '0') : len <= 255 ? '4c' + len.toString(16).padStart(2, '0') : '4d' + (len & 255).toString(16).padStart(2, '0') + (len >> 8).toString(16).padStart(2, '0');
  const cb = structuredClone(block.transactions[0]); cb.outputs[c.index].scriptPubKey = c.spk.slice(0, 76) + op + push;
  return { ...block, transactions: [cb, ...block.transactions.slice(1)] };
}

// SPEC 4: the block data is sha256 of the first 72 header bytes (version, prev, merkle root,
// time on wire) with the merkle root recomputed over the coinbase stripped of its solution
export function blockData({ codec, hash }, block) {
  const c = commitmentOutput(block);
  const cb = structuredClone(block.transactions[0]); if (c) cb.outputs[c.index].scriptPubKey = c.spk.slice(0, 76);
  const root = codec.merkleRoot([codec.txid(cb), ...block.transactions.slice(1).map((t) => codec.txid(t))]);
  const bytes = codec.encode('BlockHeader', { ...block.header, merkleRoot: root }).slice(0, 72);
  return hash.bytesToHex(hash.sha256(bytes));
}

// BIP 325's shape: a virtual output paying the challenge, spent by a virtual transaction whose
// input carries the solution; the block data sits in to_spend's scriptSig
export function virtualTxs({ codec }, data, challenge, witness = []) {
  const toSpend = { version: 0, inputs: [{ prevout: { txid: NULL32, vout: 0xffffffff }, scriptSig: '0020' + data, sequence: 0 }], outputs: [{ value: 0, scriptPubKey: challenge }], lockTime: 0 };
  const prevout = { value: 0, scriptPubKey: challenge };
  const toSign = { version: 0, inputs: [{ prevout: { txid: codec.txid(toSpend), vout: 0 }, scriptSig: '', sequence: 0 }], outputs: [{ value: 0, scriptPubKey: '6a' }], lockTime: 0, witness: [witness] };
  return { toSpend, toSign, prevout };
}

// height push for the coinbase (BIP 34), then a marker
const heightPush = (h) => { const out = []; let n = h; while (n > 0) { out.push(n & 0xff); n >>>= 8; } if (out.length && out[out.length - 1] & 0x80) out.push(0); if (!out.length) return '00'; return hex(Uint8Array.from([out.length, ...out])); };
// the height a coinbase scriptSig pushes first (BIP 34): the inverse of heightPush. A scriptSig
// that does not start with a height push is refused, never read as height 0: beside a stock
// parent the coinbase is the only place the height is written.
export function coinbaseHeight(coinbase) {
  const sig = coinbase?.inputs?.[0]?.scriptSig ?? ''; if (!sig.length || sig.length % 2 || !/^[0-9a-f]*$/i.test(sig)) throw new Error('coinbase scriptSig is not a hex script');
  const b = unhex(sig); const n = b[0];
  if (n === 0) return 0; if (n >= 0x51 && n <= 0x60) return n - 0x50; // OP_0, OP_1..OP_16
  if (n > 75 || n < 1 || b.length < 1 + n) throw new Error('coinbase scriptSig does not start with a height push');
  if (n > 1 && b[n] === 0 && !(b[n - 1] & 0x80)) throw new Error('coinbase height push is not minimal'); // a padding byte only after a high bit
  if (b[n] & 0x80) throw new Error('coinbase height push is negative'); // BIP34: a ScriptNum; the top bit of the last byte is the sign
  let h = 0; for (let i = n; i >= 1; i--) h = h * 256 + b[i]; return h;
}
// a block's height: the v2 header carries it; the stock header does not, so the coinbase says
export function blockHeight(block) { return block.header.height ?? coinbaseHeight(block.transactions[0]); }

// an unsigned block on `prev` with these transactions; outputs: the coinbase's, then the witness
// commitment (the solution is appended by signBlock). The header's shape follows the parent's
// family (SPEC 3.2, parents.mjs): the 164-byte v2 header with its BLAKE2b fields beside a BLAKE2b
// parent, the stock 80-byte header, version with bit 31 clear, beside stock Bitcoin.
export function buildBlock({ k, hash, parent = null }, { height, prev, time, transactions, outputs, bits, marker = 'sidestr' }) {
  const wtxids = [NULL32, ...transactions.map((t) => k.codec.wtxid(t))];
  const root = hash.hexToBytes(k.codec.merkleRoot(wtxids)).reverse(); const cat = new Uint8Array(64); cat.set(root);
  const commitment = hash.bytesToHex(hash.dsha256(cat));
  const tag = hash.bytesToHex(new TextEncoder().encode(marker));
  const coinbase = { version: 2, inputs: [{ prevout: { txid: NULL32, vout: 0xffffffff }, scriptSig: heightPush(height) + (tag.length / 2).toString(16).padStart(2, '0') + tag, sequence: 0xffffffff }],
    outputs: [...outputs, { value: 0, scriptPubKey: '6a24aa21a9ed' + commitment }], witness: [[NULL32]], lockTime: 0 };
  const txs = [coinbase, ...transactions];
  const merkleRoot = k.codec.merkleRoot(txs.map((t) => k.codec.txid(t)));
  const family = parent?.family ?? (k.params?.powHash === 'knots:blake2b-v2' ? 'blake2b' : 'stock');
  const header = family === 'blake2b'
    ? { version: 0xa0000000, prevBlockHash: prev, merkleRoot, timeOnWire: time, bits, nonce: 0, nonce2: 0, nonce3: 0,
        extranonce: '00'.repeat(16), timeOffset: 0, txCount: txs.length, flags: 0, xorKeyMaskClearBits: 0, xorKey: '00'.repeat(16), height, mmRhs: NULL32 }
    : { version: 0x20000000, prevBlockHash: prev, merkleRoot, time, bits, nonce: 0 };
  return { header, transactions: txs };
}

// sign with the challenge key (key path, no tweak: the challenge is 5120‖pubkey), then satisfy
// the proof of work
// what a block signature signs: the taproot sighash of the virtual transaction, for the key path
// (level 1) or for a leaf of the challenge (level 2: `leafHash` of the multi_a leaf)
export function blockSigHash({ k, hash, interpreter }, block, challenge, leafHash = null) {
  const data = blockData({ codec: k.codec, hash }, block);
  const { toSign, prevout } = virtualTxs({ codec: k.codec }, data, challenge);
  let msg = interpreter.sighashTaproot(toSign, 0, [prevout], 0x00, leafHash ? { leafHash } : {}); if (typeof msg === 'string') msg = hash.hexToBytes(msg);
  return msg;
}
// a block with its witness in place: the solution appended, the merkle root recomputed, the header
// nonce found for powLimit
export function sealBlock({ k }, block, witnessItems) {
  let signed = withSolution(block, witnessItems);
  signed.header = { ...signed.header, merkleRoot: k.codec.merkleRoot(signed.transactions.map((t) => k.codec.txid(t))) };
  const target = k.codec.expandCompact(signed.header.bits);
  for (let nonce = 0; nonce < 0xffffffff; nonce++) { signed.header.nonce = nonce; if (BigInt('0x' + k.codec.blockHash(signed.header)) <= target) break; }
  return signed;
}
export function signBlock({ k, hash, interpreter, schnorrSign }, block, challenge, privHex) {
  const msg = blockSigHash({ k, hash, interpreter }, block, challenge);
  const sig = hash.bytesToHex(schnorrSign(msg, privHex));
  let signed = withSolution(block, [sig]);
  signed.header = { ...signed.header, merkleRoot: k.codec.merkleRoot(signed.transactions.map((t) => k.codec.txid(t))) };
  const target = k.codec.expandCompact(signed.header.bits);
  for (let nonce = 0; nonce < 0xffffffff; nonce++) { signed.header.nonce = nonce; if (BigInt('0x' + k.codec.blockHash(signed.header)) <= target) break; }
  return signed;
}
