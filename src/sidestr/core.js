/**
 * Podkey - sidestr browser signer core (proposals/browser-signer.md in sidestr/spec)
 *
 * Everything the spend window decides, with no DOM and no chrome.* so Node can
 * test it: open a chain from its id alone, read what the person's coins carry,
 * review an unsigned transaction against the chain Podkey validated itself,
 * and assemble the signed result. The page supplies only the chain id and the
 * transaction; every coin, amount, asset and sighash here comes from Podkey's
 * own reading of the chain.
 *
 * The engine is the one the sidestr explorer and wallet run, vendored under
 * vendor/sidestr/ (scripts/vendor-sidestr.js): an extension may not load code
 * from the network.
 */

import { hexToNpub } from '../keyformat.js';
import { SpendError } from './request.js';

export { CODES, SpendError, checkRequest, MAX_TX_HEX } from './request.js';

/** A fee at or above this many sats, or above the sats a plain payment sends, is flagged. */
export const LARGE_FEE = 5_000;

/** The relays sidestr's wallet asks for tip announcements (SPEC 11). */
export const RELAYS = ['wss://nos.lol', 'wss://relay.damus.io', 'wss://relay.primal.net', 'wss://nostr.mom', 'wss://nostr.oxtr.dev'];

/**
 * Load the vendored engine. `base` is the vendor/sidestr/ directory as a URL
 * (the extension's own files in the spend window, file: URLs in tests).
 */
export async function loadLib (base = new URL('../../vendor/sidestr/', import.meta.url)) {
  const at = (p) => new URL(p, base).href;
  const [explorer, announce, txsign, records, assets, parents, nostr, secp] = await Promise.all([
    import(at('explorer/explorer.mjs')),
    import(at('spec/siding/lib/announce.mjs')),
    import(at('spec/siding/lib/txsign.mjs')),
    import(at('spec/siding/lib/records.mjs')),
    import(at('spec/siding/lib/overlays/assets.mjs')),
    import(at('spec/siding/lib/parents.mjs')),
    import(at('schema/codec/nostr.js')),
    import(at('schema/codec/secp256k1.js'))
  ]);
  return { explorer, announce, txsign, records, assets, parents, nostr, secp };
}

/**
 * Open a chain from its id, as SPEC 11 says, and validate every block.
 *
 * `pinned` is the signer Podkey settled on the first time this person spent on
 * this chain, or null. A chain id is a name, not a proof: with a pin only that
 * signer's announcements count, and an announcement for the same id by anyone
 * else is refused rather than followed.
 *
 * @returns {Promise<{ex, signer, announced, mirror, parent, mirrorNote}>}
 */
export async function openChain ({ lib, chainId, pinned = null, relays = RELAYS, fetchJson, loadJson, onProgress = () => {} }) {
  const { announce, explorer, parents, nostr } = lib;
  const verify = nostr.verifyNostrEvent;
  onProgress(`Asking ${relays.length} relays where ${chainId} is`);
  let found;
  try {
    found = await announce.findChain({ relays, chainId, verify, signer: pinned ?? undefined, ...(fetchJson ? { fetchJson } : {}) });
  } catch (e) {
    if (pinned) {
      // nothing from the pinned signer: say so plainly if someone else now announces this id
      let other = null;
      try { other = await announce.fetchLatestTip({ relays, chainId, verify }); } catch { /* no other announcement either */ }
      if (other && other.pubkey !== pinned) {
        throw new SpendError('unsupported', `${chainId} is now announced by a different signer (${other.pubkey.slice(0, 12)}…) than the one you first spent with (${pinned.slice(0, 12)}…). Podkey will not follow it.`);
      }
    }
    throw new SpendError('unavailable', `Could not find ${chainId}: ${e.message}`);
  }
  let parent;
  try { parent = parents.resolveParent(found.chain.parent); } catch (e) { throw new SpendError('unsupported', e.message); }
  if (parent.mainnet) throw new SpendError('unsupported', `${chainId} sits beside ${parent.label}. Podkey signs only for chains beside test networks for now.`);

  onProgress(`Checking every block of ${chainId}`);
  const ex = new explorer.Explorer(found.mirror, loadJson ? { loadJson } : {});
  try {
    await ex.open();
  } catch (e) {
    if (e.code === 'unsupported' || /names rule|rule needs/.test(e.message)) throw new SpendError('unsupported', e.message);
    throw new SpendError('unavailable', `Could not read ${chainId} from ${found.mirror}: ${e.message}`);
  }
  if (ex.chain.id !== chainId || ex.chain.signer !== found.tip.pubkey) {
    throw new SpendError('unavailable', `The mirror ${found.mirror} does not serve ${chainId} as its signer announced it.`);
  }
  const bad = ex.blocks.find((b) => b && b.verdict && b.verdict.ok === false);
  if (bad) throw new SpendError('unavailable', `Block ${bad.height} of ${chainId} failed validation; Podkey will not sign against it.`);
  const tip = ex.tip();
  const judged = announce.judgeMirror({ announced: found.tip, height: tip.height, headerHex: ex.headerHex(tip.height) });
  if (judged.ok === false) throw new SpendError('unavailable', `The mirror contradicts ${chainId}'s signer: ${judged.note}`);
  return { ex, signer: found.tip.pubkey, announced: found.tip, mirror: found.mirror, parent, mirrorNote: judged.note };
}

const outpoint = (inp) => `${inp.prevout.txid}:${inp.prevout.vout}`;

/**
 * What each unspent output carries (SPEC 12). On a chain that names the
 * `assets` rule this is the rule's own state. On one that names no rules it is
 * the holders' reading of the same records: a transaction that breaks the rule
 * keeps its spends and carries nothing, so what it tried to move is destroyed
 * (the view sidestr-core's AssetView takes, so the two agree).
 */
export function assetView (ex, lib) {
  const { assets } = lib;
  if (ex.rules?.assets) {
    const r = ex.rules.assets;
    return { mode: 'rule', carried: r.carried, issued: r.issued, check: r.check, CarryView: assets.CarryView };
  }
  const ov = assets.assetsOverlay(ex.chain);
  for (let h = 0; h < ex.blocks.length; h++) {
    const b = ex.blocks[h];
    if (!b?.block) throw new SpendError('unavailable', `Block ${h} is not in memory; the asset view needs every block.`);
    const view = new assets.CarryView(ov.carried);
    b.block.transactions.forEach((tx, i) => {
      if (i === 0) return; // a coinbase carries nothing
      const txid = b.txids[i];
      const r = ov.check(tx, txid, view);
      if (!r.ok) { for (const inp of tx.inputs) view.spend(outpoint(inp)); return; }
      if (r.issue) ov.issued.set(txid, { ticker: r.issue.ticker, decimals: r.issue.decimals, height: h });
    });
    for (const [k, v] of view.temp) if (!view.spent.has(k)) ov.carried.set(k, v);
    for (const k of view.spent.keys()) ov.carried.delete(k);
  }
  return { mode: 'view', carried: ov.carried, issued: ov.issued, check: ov.check, CarryView: assets.CarryView };
}

const addAll = (into, from) => { for (const [a, n] of from ?? []) into.set(a, (into.get(a) ?? 0) + n); return into; };

/** An asset amount in its own units, e.g. 1.50 for 150 at 2 decimals. */
export function formatAsset (amount, decimals = 0) {
  if (!decimals) return amount.toLocaleString('en-GB');
  const s = String(amount).padStart(decimals + 1, '0');
  const whole = Number(s.slice(0, -decimals)).toLocaleString('en-GB');
  return `${whole}.${s.slice(-decimals)}`;
}

/**
 * Review an unsigned transaction for `pub` against the validated chain.
 *
 * Refuses (`not-yours`) any input that is not an unspent, mature coin in
 * Podkey's own set paying `5120‖pub`, and (`invalid`) anything it cannot read
 * or that the chain's own asset rule would refuse. Returns what the window
 * shows and the sighashes to sign, computed here from Podkey's own prevouts.
 */
export function review ({ ex, lib, view, pub, txHex }) {
  const { txsign, records, explorer } = lib;
  const k = ex.k;
  if (!/^[0-9a-f]{64}$/.test(pub)) throw new SpendError('unavailable', 'No public key');
  const me = `5120${pub}`;
  let tx;
  try { tx = k.codec.decode('Transaction', txHex); } catch (e) { throw new SpendError('invalid', `Not a transaction: ${e.message}`); }
  if (!tx?.inputs?.length || !tx?.outputs?.length) throw new SpendError('invalid', 'A transaction needs inputs and outputs');
  tx.witness = []; // any witness the page sent is ignored and replaced
  const txid = k.codec.txid(tx);

  const tip = ex.tip().height; const maturity = k.params.coinbaseMaturity;
  const seen = new Set(); const coins = [];
  for (const inp of tx.inputs) {
    const key = outpoint(inp);
    if (seen.has(key)) throw new SpendError('invalid', `Input ${key.slice(0, 12)}… is spent twice`);
    seen.add(key);
    const c = ex.utxo.get(key);
    if (!c) throw new SpendError('not-yours', `Input ${key.slice(0, 12)}… is not an unspent coin on ${ex.chain.id} (spent, unconfirmed or never made)`);
    if (c.output.scriptPubKey !== me) throw new SpendError('not-yours', `Input ${key.slice(0, 12)}… is not your coin`);
    if (c.coinbase && tip + 1 - c.height < maturity) throw new SpendError('not-yours', `Input ${key.slice(0, 12)}… is a block reward that is not mature yet`);
    coins.push({ key, value: c.output.value, carries: view.carried.get(key) ?? null });
  }
  const prevouts = coins.map((c) => ({ value: c.value, scriptPubKey: me }));
  const inSum = coins.reduce((s, c) => s + c.value, 0);
  const outSum = tx.outputs.reduce((s, o) => s + o.value, 0);
  const fee = inSum - outSum;
  if (fee < 0) throw new SpendError('invalid', 'The outputs spend more than the inputs hold');

  // assets: what the inputs carry, what the tallies assign, and what is destroyed
  const r = view.check(tx, txid, new view.CarryView(view.carried));
  const inCarry = new Map(); for (const c of coins) addAll(inCarry, c.carries);
  if (!r.ok && view.mode === 'rule') throw new SpendError('invalid', `${ex.chain.id} would refuse this transaction: ${r.error}`);
  const assigned = new Map(); if (r.ok) for (const m of r.out.values()) addAll(assigned, m);
  const destroyed = [];
  for (const [asset, n] of inCarry) { const left = n - (assigned.get(asset) ?? 0); if (left > 0) destroyed.push({ asset, amount: left }); }
  const label = (asset) => {
    const i = view.issued.get(asset) ?? (r.ok && r.issue && asset === txid ? r.issue : null);
    return { asset, ticker: i?.ticker ?? `${asset.slice(0, 8)}…`, decimals: i?.decimals ?? 0 };
  };

  const hrp = ex.chain.addressPrefix;
  const outputs = tx.outputs.map((o, vout) => {
    const spk = o.scriptPubKey; const carries = r.ok ? (r.out.get(vout) ?? null) : null;
    const assetsOut = carries ? [...carries].map(([asset, amount]) => ({ ...label(asset), amount })) : [];
    const base = { vout, value: o.value, script: spk, assets: assetsOut };
    if (spk === me) return { ...base, kind: 'change' };
    if (spk.startsWith('6a')) {
      const text = records.recordText(spk);
      if (text?.startsWith('pegout:')) return { ...base, kind: 'pegout', text, to: text.slice(7) };
      if (text && /^(issue|tally|pool):/.test(text)) return { ...base, kind: 'asset-record', text };
      return { ...base, kind: o.value > 0 ? 'burn' : 'record', text };
    }
    const key = /^5120([0-9a-f]{64})$/.exec(spk);
    const address = explorer.scriptToAddress(spk, hrp);
    if (key) return { ...base, kind: 'key', pubkey: key[1], npub: hexToNpub(key[1]), address };
    return { ...base, kind: 'script', address };
  });

  const toOthers = outputs.filter((o) => o.kind === 'key' || o.kind === 'script').reduce((s, o) => s + o.value, 0);
  const warnings = [];
  for (const d of destroyed) {
    const l = label(d.asset);
    warnings.push({ kind: 'destroys', text: `This destroys ${formatAsset(d.amount, l.decimals)} ${l.ticker} that your coins carry.`, ...l, amount: d.amount });
  }
  if (!r.ok) warnings.push({ kind: 'breaks', text: `This breaks the asset rule (${r.error}), so everything your coins carry is destroyed.` });
  for (const o of outputs) {
    if (o.kind === 'burn') warnings.push({ kind: 'burn', text: `Output ${o.vout} burns ${o.value.toLocaleString('en-GB')} sats for good.` });
    if (o.kind === 'pegout') warnings.push({ kind: 'pegout', text: `Output ${o.vout} is a peg-out: ${o.value.toLocaleString('en-GB')} sats burn here and are owed on the parent chain.` });
  }
  // Against the sats sent only when no asset goes with them: an asset rides on a
  // few hundred sats of carrier, and a normal fee is not "more than it sends".
  const sendsAssets = outputs.some((o) => (o.kind === 'key' || o.kind === 'script') && o.assets.length);
  if (fee >= LARGE_FEE || (!sendsAssets && toOthers > 0 && fee > toOthers)) warnings.push({ kind: 'fee', text: `The fee is ${fee.toLocaleString('en-GB')} sats${toOthers > 0 ? `, more than the ${toOthers.toLocaleString('en-GB')} sats this sends` : ''}.` });

  const sighashes = tx.inputs.map((_, i) => {
    const { m, ht } = txsign.keyPathSighash({ k, hash: ex.hash }, tx, i, prevouts);
    return { digest: ex.hash.bytesToHex(m), ht };
  });

  return {
    tx, txid, prevouts, fee, inSum, outSum, toOthers,
    inputs: coins.map((c) => ({ ...c, carries: c.carries ? [...c.carries].map(([asset, amount]) => ({ ...label(asset), amount })) : [] })),
    outputs, destroyed, warnings, sighashes,
    assetMode: view.mode
  };
}

/**
 * Put the signatures on and check them as a validator would. `signatures` are
 * 64-byte BIP 340 signatures as hex, one per input, over the review's digests.
 * @returns {{ tx: string, txid: string }}
 */
export function finish ({ ex, lib, reviewed, signatures, pub }) {
  const { txsign } = lib; const k = ex.k;
  if (!Array.isArray(signatures) || signatures.length !== reviewed.sighashes.length || !signatures.every((s) => /^[0-9a-f]{128}$/.test(s))) {
    throw new SpendError('unavailable', 'The key did not return one signature per input');
  }
  const tx = { ...reviewed.tx, witness: signatures.map((s, i) => [s + reviewed.sighashes[i].ht.toString(16).padStart(2, '0')]) };
  if (!txsign.verifyKeyPath({ k, hash: ex.hash, secp: lib.secp }, tx, reviewed.prevouts, pub)) {
    throw new SpendError('unavailable', 'A signature did not verify; nothing was returned');
  }
  const txid = k.codec.txid(tx);
  if (txid !== reviewed.txid) throw new SpendError('unavailable', 'Signing changed the transaction id; nothing was returned');
  return { tx: k.codec.encodeHex('Transaction', tx), txid };
}
