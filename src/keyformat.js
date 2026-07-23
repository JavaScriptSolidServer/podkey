/**
 * Podkey - private-key input normalisation
 *
 * A user importing an existing key may paste it in either of the two forms that
 * are in the wild: raw 64-char hex, or the NIP-19 `nsec1…` bech32 form that most
 * Nostr apps display. Podkey stores and operates on hex internally, so this
 * module converts either input into canonical lowercase hex at the import
 * boundary. The `nsec` case is handled transparently — the caller does not treat
 * it as an error or nag the user about format.
 *
 * Self-contained bech32 (BIP-173) decoder so the extension keeps its
 * dependency-light footprint (only @noble primitives elsewhere). NIP-19 uses the
 * original bech32 checksum constant (1), not bech32m.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32_CONST = 1;

function polymod (values) {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GENERATOR[i];
    }
  }
  return chk >>> 0;
}

function hrpExpand (hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

/**
 * Decode a bech32 string into its human-readable part and 5-bit data words
 * (checksum stripped). Throws on any structural or checksum error.
 * @param {string} str
 * @returns {{ hrp: string, words: number[] }}
 */
function bech32Decode (str) {
  if (typeof str !== 'string' || str.length < 8 || str.length > 1000) {
    throw new Error('Invalid key');
  }
  // Reject mixed case per BIP-173; normalise to lowercase for lookup.
  const lower = str.toLowerCase();
  const upper = str.toUpperCase();
  if (str !== lower && str !== upper) {
    throw new Error('Invalid key');
  }
  const s = lower;

  const sep = s.lastIndexOf('1');
  if (sep < 1 || sep + 7 > s.length) {
    throw new Error('Invalid key');
  }
  const hrp = s.slice(0, sep);
  const dataPart = s.slice(sep + 1);

  const words = [];
  for (const ch of dataPart) {
    const v = CHARSET.indexOf(ch);
    if (v === -1) throw new Error('Invalid key');
    words.push(v);
  }

  if (polymod(hrpExpand(hrp).concat(words)) !== BECH32_CONST) {
    throw new Error('Invalid key');
  }

  return { hrp, words: words.slice(0, words.length - 6) };
}

/**
 * Regroup a stream of `from`-bit words into `to`-bit words. Used to turn the
 * 5-bit bech32 words back into 8-bit bytes (pad=false, no leftover bits).
 * @param {number[]} data
 * @param {number} from
 * @param {number} to
 * @param {boolean} pad
 * @returns {number[]}
 */
function convertBits (data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || value >>> from !== 0) throw new Error('Invalid key');
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    throw new Error('Invalid key');
  }
  return out;
}

function bytesToHex (bytes) {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Decode an `nsec1…` (NIP-19) private key into 64-char lowercase hex.
 * @param {string} nsec
 * @returns {string} 64-char hex private key
 */
export function nsecToHex (nsec) {
  const { hrp, words } = bech32Decode(nsec);
  if (hrp !== 'nsec') {
    throw new Error('Invalid key');
  }
  const bytes = convertBits(words, 5, 8, false);
  if (bytes.length !== 32) {
    throw new Error('Invalid key');
  }
  return bytesToHex(bytes);
}

/**
 * Normalise a pasted private key into canonical 64-char lowercase hex, accepting
 * either raw hex or an `nsec1…` bech32 key. The nsec form is converted inline so
 * an existing-key import "just works" regardless of which form the user pasted.
 * Throws a neutral `Invalid key` on anything that is neither.
 * @param {string} input
 * @returns {string} 64-char hex private key
 */
export function normalizeSecretKeyToHex (input) {
  if (typeof input !== 'string') {
    throw new Error('Invalid key');
  }
  const s = input.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    return s.toLowerCase();
  }
  // Case-insensitive prefix match; bech32Decode enforces the (non-mixed) case
  // rule and checksum. NIP-19 keys are lowercase in practice, but an all-caps
  // paste is still valid bech32, so accept it rather than reject a real key.
  if (/^nsec1[0-9a-z]+$/i.test(s)) {
    return nsecToHex(s);
  }
  throw new Error('Invalid key');
}
