// The `pool` rule (SPEC 12.3): a pool is one OP_TRUE coin holding x sats and y of one asset; a
// transaction spends at most one pool coin and leaves exactly one, as a swap (constant product,
// 3 per 1000 on what comes in), an add or a remove (shares pro rata, rounded to the pool's favour).
// Shares are the asset whose id is the pool id. State: pools, derived from the chain on open.
import { classify, isqrt } from '../records.mjs';
export const RULE = 'sidestr:rule-pool', POOL_SCRIPT = '51';
const key = (txid, vout) => `${txid}:${vout}`;
const B = (n) => BigInt(n);

export function poolOverlay(chain, { assets, pools = new Map() }) {
  // pools: pool id -> { asset, x, y, shares, outpoint, opened }; shared with the assets rule, which exempts share assets
  const byOutpoint = new Map(); // pool coin outpoint -> pool id
  const journal = new Map();   // height -> [{ id, before }] to undo a re-validated height
  // check one transaction; `view` is the assets CarryView already holding this tx's outputs (the assets check ran first)
  function check(tx, txid, view, { coinbase = false, apply = () => {} } = {}) {
    const cls = classify(tx); const bad = (error) => ({ ok: false, error });
    if (coinbase) return cls.pools.length ? bad('the coinbase carries no records') : { ok: true };
    const spent = tx.inputs.map((i) => byOutpoint.get(key(i.prevout.txid, i.prevout.vout))).filter(Boolean);
    if (spent.length > 1) return bad('a transaction spends at most one pool coin');
    const opening = cls.pools.filter((p) => p.pool === 'self'), continuing = cls.pools.filter((p) => p.pool !== 'self');
    if (cls.pools.length > 1) return bad('a transaction carries at most one pool: record');
    if (!spent.length && !cls.pools.length) return { ok: true };
    const carriedOn = (vout) => view.get(key(txid, vout)) ?? new Map();
    const sharesIn = (id) => { let s = 0; for (const i of tx.inputs) { const c = view.before(key(i.prevout.txid, i.prevout.vout)); if (c?.has(id)) s += c.get(id); } return s; };
    const sharesOut = (id) => { let s = 0; for (const [, m] of viewOutputs(view, txid, tx)) if (m.has(id)) s += m.get(id); return s; };
    if (opening.length) {
      if (spent.length) return bad('a transaction opens a pool or spends one, not both');
      const { vout } = opening[0]; const o = tx.outputs[vout]; if (!o || o.scriptPubKey !== POOL_SCRIPT || !(o.value >= 1)) return bad('the pool coin is an OP_TRUE output with value');
      const m = carriedOn(vout); if (m.size !== 1) return bad('a pool coin carries exactly one asset'); const [asset, y0] = [...m][0]; if (asset === txid) return bad('a pool does not hold its own shares');
      const shares = isqrt(B(o.value) * B(y0)); if (B(sharesOut(txid)) !== shares) return bad(`opening tallies exactly ${shares} shares (tally:self)`);
      return { ok: true, effect: { id: txid, asset, x: o.value, y: y0, shares: Number(shares), outpoint: key(txid, vout), opened: true } };
    }
    // continuing: the spent pool is recreated
    if (!spent.length) return bad('pool: names a pool this transaction does not spend');
    const id = spent[0], p = pools.get(id); if (!continuing.length || continuing[0].pool !== id) return bad('a spent pool coin is recreated with pool:<its id>:<vout>');
    const { vout } = continuing[0]; const o = tx.outputs[vout]; if (!o || o.scriptPubKey !== POOL_SCRIPT || !(o.value >= 1)) return bad('the pool coin is an OP_TRUE output with value');
    const m = carriedOn(vout); if (m.size !== 1 || !m.has(p.asset)) return bad('the pool coin carries exactly its asset'); const x = B(p.x), y = B(p.y), x2 = B(o.value), y2 = B(m.get(p.asset));
    if (y2 < 1n) return bad('a pool is never emptied');
    const S = B(p.shares), S2 = S - B(sharesIn(id)) + B(sharesOut(id)); if (S2 < 0n) return bad('more shares destroyed than exist');
    let kind;
    if (S2 === S) { const dx = x2 > x ? x2 - x : 0n, dy = y2 > y ? y2 - y : 0n; if ((1000n * x2 - 3n * dx) * (1000n * y2 - 3n * dy) < 1000000n * x * y) return bad('swap: the constant product does not hold after the fee'); kind = 'swap'; }
    else if (S2 > S) { if (x2 < x || y2 < y) return bad('add: the pool does not shrink'); const lim = (a, b) => (a - b) * S / b; const cap = [lim(x2, x), lim(y2, y)].reduce((a, b) => a < b ? a : b); if (S2 - S > cap) return bad(`add: at most ${cap} shares for what was added`); kind = 'add'; }
    else { if (x2 > x || y2 > y) return bad('remove: the pool does not grow'); const d = S - S2; if (x - x2 > x * d / S || y - y2 > y * d / S) return bad('remove: more than the shares\' pro-rata part'); kind = 'remove'; }
    return { ok: true, kind, effect: { id, asset: p.asset, x: Number(x2), y: Number(y2), shares: Number(S2), outpoint: key(txid, vout), opened: p.opened } };
  }
  // this transaction's outputs as the view holds them (assets check wrote them)
  function viewOutputs(view, txid, tx) { const out = []; tx.outputs.forEach((_, vout) => { const m = view.get(key(txid, vout)); if (m) out.push([vout, m]); }); return out; }
  function apply(effect, height, log) { const before = pools.get(effect.id) ?? null; log?.push({ id: effect.id, before }); if (before) byOutpoint.delete(before.outpoint); pools.set(effect.id, { ...effect }); byOutpoint.set(effect.outpoint, effect.id); }
  return {
    graph: { '@id': 'sidestr:overlay-pool', '@context': { sidestr: 'https://sidestr.com/ns#' }, '@graph': [
      { '@id': RULE, '@type': 'ValidationRule', ruleSet: 'btc:BlockContextRules', label: 'pool', errorCode: 'bad-pool',
        comment: 'A transaction spends at most one pool coin and recreates it: a swap keeps the constant product after a fee of 3 per 1000, an add mints shares pro rata, a remove withdraws pro rata and never empties the pool (SPEC 12.3).' } ] },
    pools, byOutpoint, journal, check, apply, // journal: height -> [{ id, before }] for every applied height, so a page can replay a pool's history (trades, adds, removes)
    installChecks({ blocks, codec }) {
      blocks.registerChecks({ blockContext: { [RULE]: ({ block, height }) => {
        for (const { id, before } of (journal.get(height) ?? []).reverse()) { const cur = pools.get(id); if (cur) byOutpoint.delete(cur.outpoint); if (before) { pools.set(id, before); byOutpoint.set(before.outpoint, id); } else pools.delete(id); }
        // the assets rule ran first for this block: its view holds this block's outputs and what the spent inputs carried
        const view = assets.lastHeight === height && assets.lastView ? assets.lastView : new assets.CarryView(assets.carried); const log = []; journal.set(height, log);
        for (let i = 0; i < block.transactions.length; i++) { const tx = block.transactions[i]; const r = check(tx, codec.txid(tx), view, { coinbase: i === 0 }); if (!r.ok) return false; if (r.effect) apply(r.effect, height, log); }
        return true;
      } } });
    },
  };
}
