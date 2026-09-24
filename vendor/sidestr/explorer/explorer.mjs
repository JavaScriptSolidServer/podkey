// Reads a sidestr chain from a mirror (chain.json, blocks.json, blocks.dat with Range) and validates
// every block with the engine in memory: headers, structure including the block signature, and
// context against a UTXO set it builds itself. No key, no submit, no DOM: index.html renders this.
export const CDN = new URL('../schema', import.meta.url).href; // Podkey: the vendored engine, never the network
export const SIDESTR = new URL('../spec/siding/lib', import.meta.url).href; // Podkey: the vendored lib

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const polymod = (values) => { const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let chk = 1; for (const v of values) { const top = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= G[i]; } return chk >>> 0; };
const hrpExpand = (hrp) => { const out = []; for (const c of hrp) out.push(c.charCodeAt(0) >>> 5); out.push(0); for (const c of hrp) out.push(c.charCodeAt(0) & 31); return out; };
const toWords = (bytes) => { const out = []; let acc = 0, bits = 0; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out.push((acc >>> bits) & 31); } } if (bits) out.push((acc << (5 - bits)) & 31); return out; };
const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
export function scriptToAddress(spk, hrp) {
  const m = /^(00|5[1-9a-f]|60)([0-9a-f]{2})([0-9a-f]+)$/i.exec(spk); if (!m) return null;
  const version = m[1] === '00' ? 0 : parseInt(m[1], 16) - 0x50, len = parseInt(m[2], 16), program = m[3];
  if (program.length !== len * 2 || len < 2 || len > 40) return null;
  const words = [version, ...toWords(unhex(program))]; const pm = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ (version === 0 ? 1 : 0x2bc830a3);
  const chk = []; for (let i = 0; i < 6; i++) chk.push((pm >>> (5 * (5 - i))) & 31);
  return hrp + '1' + [...words, ...chk].map((w) => CHARSET[w]).join('');
}
export function addressToScript(addr, hrp) {
  const s = addr.toLowerCase(); if (!s.startsWith(hrp + '1')) return null;
  const data = [...s.slice(hrp.length + 1)].map((c) => CHARSET.indexOf(c)); if (data.some((d) => d < 0) || data.length < 7) return null;
  const words = data.slice(0, -6), version = words[0]; const bytes = []; let acc = 0, bits = 0;
  for (const w of words.slice(1)) { acc = (acc << 5) | w; bits += 5; while (bits >= 8) { bits -= 8; bytes.push((acc >>> bits) & 255); } }
  const prog = bytes.map((b) => b.toString(16).padStart(2, '0')).join(''); const op = version === 0 ? '00' : (0x50 + version).toString(16);
  return op + (bytes.length).toString(16).padStart(2, '0') + prog;
}
export const opReturnText = (spk) => { const m = /^6a(?:4c)?([0-9a-f]{2})([0-9a-f]*)$/i.exec(spk); if (!m) return null; const b = unhex(m[2]); const t = new TextDecoder().decode(b); return /^[\x20-\x7e]+$/.test(t) ? t : null; };

// `opts` lets a test point at local checkouts: { cdn, sidestr, loadJson(url) }
export async function loadEngine(chain, opts = {}) {
  const cdn = opts.cdn ?? CDN, side = opts.sidestr ?? SIDESTR, j = opts.loadJson ?? (async (u) => (await fetch(u)).json());
  const [{ createKernel }, { resolveParent }, { sidestrOverlay }, hash, nostr, { rulesFor }, secp] = await Promise.all([import(`${cdn}/codec/kernel.js`), import(`${side}/parents.mjs`), import(`${side}/overlay.mjs`), import(`${cdn}/codec/hash.js`), import(`${cdn}/codec/nostr.js`), import(`${side}/overlays/index.mjs`), import(`${cdn}/codec/secp256k1.js`)]);
  const jj = (p) => j(`${cdn}/${p}`); const rules = rulesFor(chain); // SPEC 12: the rules the document names, or a refusal
  const parent = resolveParent(chain.parent); const overlays = [sidestrOverlay(chain, { hash, secp }), ...rules.overlays]; // SPEC 3.2: the header format follows the parent
  if (parent.family === 'blake2b') { const { knotsBlake2b } = await import(`${cdn}/codec/overlays/knots-blake2b.js`); overlays.unshift(knotsBlake2b(await jj('schema/overlays/knots-blake2b.jsonld'))); }
  const k = createKernel({ core: await jj('schema/core.jsonld'), proof: await jj('schema/proof.jsonld'), script: await jj('schema/script.jsonld'), chain: await jj('schema/chain.jsonld'), validate: await jj('schema/validate.jsonld'),
    network: chain.id, overlays }); // secp: a federated document's challenge is checked against its signers
  if (rules.evm) await rules.evm.init(); // the evm rule fetches ethereumjs (from jsdelivr in a page) only on a chain that names it
  return { k, hash, nostr, rules, parent };
}

// the chain as a model: blocks in order, each validated, plus indexes for the page
// bumped when a saved state could be wrong: 2 after the concurrent-refresh fix (a v1 cache may hold duplicated history)
export const CACHE_VERSION = 2;
export class Explorer {
  // opts.store: { get(key), set(key, value), delete(key) } (strings; sync or async), e.g. localStorage. With a store the
  // validated state (coins, per-script history, the last 11 headers) is saved at the tip and a later open resumes from it,
  // validating only the blocks since. The cache is dropped when the mirror's block at that height has another hash (a chain
  // reset) or the chain names rules (their state is not cached yet). `fromCache` is the height resumed from, else null.
  constructor(mirror, opts = {}) { this.opts = opts; this.mirror = mirror.replace(/\/$/, ''); this.blocks = []; this.txs = new Map(); this.utxo = new Map(); this.byScript = new Map(); this.headers = []; this.store = opts.store ?? null; this.fromCache = null; }
  get cacheKey() { return `sidestr:state:${this.chain?.id}`; }
  get cacheable() { return !!(this.store && this.chain && !(this.rules?.overlays?.length)); }
  async clearCache() { if (this.store && this.chain) await this.store.delete?.(this.cacheKey); }
  async #restore(index) {
    let c; try { const raw = await this.store.get(this.cacheKey); c = raw ? JSON.parse(raw) : null; } catch { c = null; }
    if (!c || c.v !== CACHE_VERSION || c.chain !== this.chain.id) { if (c) await this.clearCache(); return; } // an older cache format is dropped, not read
    const e = index.blocks[c.height]; if (!e || e.hash !== c.hash) { await this.clearCache(); return; } // the chain is not the one the cache saw
    this.utxo = new Map(c.utxo); this.byScript = new Map(c.byScript); for (const [h, hex] of c.headers) this.headers[h] = this.k.codec.decode('BlockHeader', hex);
    this.blocks.length = c.height + 1; this.blocks[c.height] = { height: c.height, hash: c.hash, time: c.time, cached: true, verdict: { ok: true, cached: true } }; this.fromCache = c.height;
  }
  async #save() {
    const tip = this.tip(); if (!tip) return; const headers = []; for (let h = Math.max(0, tip.height - 10); h <= tip.height; h++) if (this.headers[h]) headers.push([h, this.k.codec.encodeHex('BlockHeader', this.headers[h])]);
    try { await this.store.set(this.cacheKey, JSON.stringify({ v: CACHE_VERSION, chain: this.chain.id, height: tip.height, hash: tip.hash, time: tip.time, utxo: [...this.utxo], byScript: [...this.byScript], headers })); } catch {}
  }
  async open() {
    this.chain = await (await fetch(`${this.mirror}/chain.json`, { cache: 'no-store' })).json();
    const { k, hash, nostr, rules, parent } = await loadEngine(this.chain, this.opts); this.k = k; this.hash = hash; this.nostr = nostr; this.rules = rules; this.parent = parent;
    return this.refresh();
  }
  // one refresh at a time: a second caller waits for the first and gets its result, so a block is never applied twice
  refresh() { if (!this._refreshing) this._refreshing = this.#refresh().finally(() => { this._refreshing = null; }); return this._refreshing; }
  async #refresh() {
    const index = await (await fetch(`${this.mirror}/blocks.json`, { cache: 'no-store' })).json();
    if (this.blocks.length === 0 && this.cacheable) await this.#restore(index);
    const pending = index.blocks.filter((e) => e.height > this.blocks.length - 1);
    const fetched = new Map();
    for (let i = 0; i < pending.length; i += 16) await Promise.all(pending.slice(i, i + 16).map(async (e) => {
      const r = await fetch(`${this.mirror}/blocks.dat`, { headers: { range: `bytes=${e.offset + 8}-${e.offset + 8 + e.size - 1}` }, cache: 'no-store' });
      fetched.set(e.height, new Uint8Array(await r.arrayBuffer()));
    }));
    for (const e of pending) await this.#apply(e, fetched.get(e.height));
    this.index = index; if (pending.length && this.cacheable) await this.#save(); return this;
  }
  async #apply(entry, bytes) {
    const { k } = this; const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    const block = k.codec.decode('Block', hex); const h = entry.height; const hash = k.codec.blockHash(block.header);
    let verdict = { ok: true, failed: [], skipped: [] };
    // the evm rule executes before the kernel's checks and leaves the verdict the sync rule reads (proposals/evm.md)
    if (this.rules?.evm) { if (h === 0) { this.rules.evm.roots.set(0, this.rules.evm.roots.get(-1)); this.rules.evm.blocks.set(0, { hashes: [], root: '0x' + this.rules.evm.roots.get(-1) }); } else { const v = await this.rules.evm.prepare(block, h, k.codec); if (!v.ok) verdict.evm = v.error; } }
    if (h > 0) {
      const [hv] = k.headers.validateChain([block.header], { startHeight: h, prevContext: this.headers.slice(Math.max(0, h - 11), h).filter(Boolean), now: Math.floor(Date.now() / 1000) + 7200 });
      const s = k.blocks.validateBlockStructure(block); const c = k.blocks.validateBlockContext(block, { height: h, utxo: this.utxo, mtp: k.headers.medianTimePast(this.headers.slice(Math.max(0, h - 11), h)) });
      for (const r of [...hv.results, ...s.results, ...c.results]) { if (r.ok === false) verdict.failed.push(r.rule); if (r.ok === null) verdict.skipped.push(r.rule); }
      verdict.ok = verdict.failed.length === 0 && hash === entry.hash && block.header.prevBlockHash === this.blocks[h - 1].hash;
    }
    // fees and the spend index, from the coins as they are before this block
    let fees = 0; const spends = [];
    block.transactions.forEach((tx, i) => { if (i === 0) return; let inSum = 0; for (const inp of tx.inputs) { const key = `${inp.prevout.txid}:${inp.prevout.vout}`; const coin = this.utxo.get(key); if (coin) { inSum += coin.output.value; spends.push([key, coin, k.codec.txid(tx)]); } } fees += inSum - tx.outputs.reduce((s, o) => s + o.value, 0); });
    k.blocks.applyBlock(this.utxo, block, h);
    const txids = block.transactions.map((tx) => k.codec.txid(tx));
    const rec = { height: h, hash, time: block.header.time, size: bytes.length, txs: txids.length, fees, verdict, block, txids, coinbaseValue: block.transactions[0].outputs.reduce((s, o) => s + o.value, 0) };
    this.blocks[h] = rec; this.headers[h] = block.header;
    block.transactions.forEach((tx, i) => { const txid = txids[i]; this.txs.set(txid, { tx, txid, height: h, coinbase: i === 0, fee: i === 0 ? null : (() => { let s = 0; for (const inp of tx.inputs) { const c = spends.find((x) => x[2] === txid && x[0] === `${inp.prevout.txid}:${inp.prevout.vout}`); if (c) s += c[1].output.value; } return s - tx.outputs.reduce((a, o) => a + o.value, 0); })() });
      tx.outputs.forEach((o, vout) => { if (o.scriptPubKey.startsWith('6a')) return; const a = this.byScript.get(o.scriptPubKey) ?? { received: 0, spent: 0, outputs: [] }; a.received += o.value; a.outputs.push({ txid, vout, value: o.value, height: h }); this.byScript.set(o.scriptPubKey, a); }); });
    for (const [key, coin, txid] of spends) { const a = this.byScript.get(coin.output.scriptPubKey); if (a) { a.spent += coin.output.value; a.spends = a.spends ?? []; a.spends.push({ key, txid, value: coin.output.value, height: h }); } }
  }
  tip() { return this.blocks[this.blocks.length - 1]; }
  headerHex(h) { return this.headers[h] ? this.k.codec.encodeHex('BlockHeader', this.headers[h]) : null; }
  supply() { let s = 0; for (const c of this.utxo.values()) s += c.output.value; return s; }
  balance(spk) { let s = 0; for (const c of this.utxo.values()) if (c.output.scriptPubKey === spk) s += c.output.value; return s; }
  address(spk) { return scriptToAddress(spk, this.chain.addressPrefix) ?? spk; }
  block(ref) { return /^\d+$/.test(ref) ? this.blocks[Number(ref)] : this.blocks.find((b) => b.hash === ref); }
}
