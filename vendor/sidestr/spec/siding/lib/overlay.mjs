// The sidestr overlay for one chain document (SPEC 3, 4): a network beside its parent with
// signed blocks, no subsidy, trivial proof of work and its own address prefix. Data half: the
// network node and the signature rule joining btc:BlockRules. Code half: the check behind it.
import { blockData, solutionOf, virtualTxs } from './block.mjs';
import { resolveParent } from './parents.mjs';
import { federation } from './federation.mjs';

// --- peg-in claims (SPEC 6) --------------------------------------------------------------
// A claim is two consecutive coinbase outputs: the payout, then an OP_RETURN carrying
// `claim:<parent txid>:<vout>`. The pairing is structural, so a level-1 validator, which has no
// parent view, can still bind each claimed amount to one outpoint; a level-2 validator checks
// the pair against the parent. Coinbase value may exceed fees by exactly the paid claims.
const enc = new TextEncoder(), dec = new TextDecoder();
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
export const outpointOf = (txid, vout) => `${txid}:${vout}`;
export function claimMarker(txid, vout) { const d = enc.encode(`claim:${txid}:${vout}`); return '6a' + d.length.toString(16).padStart(2, '0') + toHex(d); }
export function opReturnData(spk) { const m = /^6a(?:4c)?([0-9a-f]{2})([0-9a-f]*)$/i.exec(spk); if (!m) return null; const b = fromHex(m[2]); return parseInt(m[1], 16) === b.length ? b : null; }
export function parseClaims(coinbase) {
  const claims = [], errors = [];
  coinbase.outputs.forEach((o, i) => {
    const d = opReturnData(o.scriptPubKey); if (!d) return; let t; try { t = dec.decode(d); } catch { return; }
    const m = /^claim:([0-9a-f]{64}):(\d{1,5})$/.exec(t); if (!m) return;
    const payout = coinbase.outputs[i - 1];
    if (!payout || payout.scriptPubKey.startsWith('6a') || !(payout.value > 0)) { errors.push(`claim at output ${i} has no payout before it`); return; }
    claims.push({ index: i, txid: m[1], vout: Number(m[2]), payout: { index: i - 1, value: payout.value, scriptPubKey: payout.scriptPubKey } });
  });
  return { claims, errors };
}

// --- peg-outs (SPEC 7) -----------------------------------------------------------------
// A burn is an OP_RETURN output carrying `pegout:<parent output script hex>` with a value: the
// value leaves the supply and the peg holders owe that script that value on the parent. The
// producer records each burn as it validates the block, by height, like claims.
export function pegoutMarker(script) { const d = enc.encode(`pegout:${script.toLowerCase()}`); return '6a' + d.length.toString(16).padStart(2, '0') + toHex(d); }
export function parsePegout(spk) {
  const d = opReturnData(spk); if (!d) return null; let t; try { t = dec.decode(d); } catch { return null; }
  const m = /^pegout:((?:[0-9a-f]{2}){2,40})$/.exec(t); return m ? m[1] : null;
}
export function parsePegouts(tx, txid) { const out = []; tx.outputs.forEach((o, i) => { const script = parsePegout(o.scriptPubKey); if (script) out.push({ txid, vout: i, script, value: o.value }); }); return out; }

export function sidestrGraph(chain) {
  return {
    '@id': 'sidestr:overlay', '@context': { sidestr: 'https://sidestr.com/ns#', knots: 'https://bitcoinknots.org/ns#' },
    '@graph': [
      {
        '@id': chain.id, '@type': 'btc:NetworkParams', extends: 'btc:regtest', label: chain.name, name: chain.name,
        comment: `sidestr chain beside ${chain.parent}: Bitcoin's rules with signed blocks (SPEC 4), no subsidy, every coin a peg.`,
        magic: chain.magic ?? 'e5d5e5d5', bech32Hrp: chain.addressPrefix, initialSubsidy: 0, halvingInterval: 210000,
        powLimit: chain.powLimit, powNoRetargeting: true, allowMinDifficultyBlocks: false,
        // the header format follows the parent (SPEC 3): beside a BLAKE2b parent, v2 headers from height 0, no headline, no reduced-data period; beside stock Bitcoin, stock headers
        ...(resolveParent(chain.parent).family === 'blake2b' ? { powHash: 'knots:blake2b-v2', structVariants: { 'btc:BlockHeader': [{ when: { field: 'version', bit: 31 }, struct: 'knots:BlockHeaderV2' }] },
          blake2bHeight: 0, blake2bHeadline: '', unifiedSighashParam: 'blake2bHeight', rdtsExpiryTime: 0 } : {}),
        sidestrParent: chain.parent, sidestrChallenge: chain.challenge, sidestrPegConfirmations: chain.pegConfirmations ?? 6, sidestrRefundBlocks: chain.refundBlocks ?? 10000,
        sidestrPegoutBlocks: chain.pegoutBlocks ?? 144, sidestrPegoutMin: chain.pegoutMin ?? 10000,
      },
      { '@id': 'sidestr:rule-pegouts', '@type': 'ValidationRule', ruleSet: 'btc:BlockContextRules', label: 'pegouts', errorCode: 'bad-pegout',
        comment: 'A pegout:<script> OP_RETURN names a parent output script of 2 to 40 bytes and carries at least pegoutMin sats; the coinbase carries none (SPEC 7). The value leaves the supply; the peg holders owe it on the parent.' },
      { '@id': 'sidestr:rule-claims', '@type': 'ValidationRule', ruleSet: 'btc:BlockContextRules', label: 'claims', errorCode: 'bad-claim',
        comment: 'Each claim:<txid>:<vout> OP_RETURN in the coinbase is immediately preceded by its payout output; no outpoint is claimed twice in the block or on the chain (SPEC 6). A level-1 validator accepts what the signers claim; a level-2 validator also checks each pair against the parent.' },
      { '@id': 'sidestr:rule-block-signature', '@type': 'ValidationRule', ruleSet: 'btc:BlockRules', label: 'block-signature', errorCode: 'bad-block-signature',
        comment: 'The coinbase witness commitment output carries, after the commitment, a push of ecc7daa2 followed by a serialized witness that satisfies the chain challenge for the block data (SPEC 4).' },
    ],
  };
}

// Level 2: a document with `signers` and `threshold` names its challenge only through them; a
// challenge that is not the derived one is a broken document. Needs the curve for the tweak.
export function checkFederation(chain, { hash, secp }) {
  if (!chain.signers) return null;
  const fed = federation({ hash, secp }, chain);
  if (chain.challenge && chain.challenge.toLowerCase() !== fed.challenge) throw new Error(`${chain.id}: challenge ${chain.challenge.slice(0, 12)}… is not the one ${chain.signers.length} signers with threshold ${chain.threshold} derive (${fed.challenge.slice(0, 12)}…)`);
  return fed;
}
export const sidestrOverlay = (chain, { hash, secp = null }) => ({
  federation: secp ? checkFederation(chain, { hash, secp }) : null,
  graph: sidestrGraph(chain),
  // outpoints claimed so far, by the height that claimed them. Validation is idempotent for one
  // height (a block re-validated, or a competing block at the same height, may claim the same
  // outpoint); a different height may not. Level 1: no reorgs, so no unwinding is needed.
  claims: new Map(),
  // burns seen so far: `${txid}:${vout}` -> { txid, vout, script, value, height }
  pegouts: new Map(),
  installChecks({ blocks, interpreter, codec, params }) {
    const claimed = this.claims, burned = this.pegouts;
    blocks.registerChecks({ blockContext: {
      'sidestr:rule-pegouts': ({ block, height }) => {
        if (block.transactions[0].outputs.some((o) => parsePegout(o.scriptPubKey))) return false;
        const found = [];
        for (const tx of block.transactions.slice(1)) { const txid = codec.txid(tx); for (const o of tx.outputs) { const d = opReturnData(o.scriptPubKey); if (!d) continue; let t = ''; try { t = dec.decode(d); } catch {} if (!t.startsWith('pegout:')) continue;
          const script = parsePegout(o.scriptPubKey); if (!script || o.value < params.sidestrPegoutMin) return false; found.push({ txid, vout: tx.outputs.indexOf(o), script, value: o.value, height }); } }
        for (const b of found) { const k = outpointOf(b.txid, b.vout); const at = burned.get(k)?.height; if (at !== undefined && at !== height) return false; burned.set(k, b); }
        return true;
      },
      'sidestr:rule-claims': ({ block, height }) => {
        const { claims, errors } = parseClaims(block.transactions[0]); if (errors.length) return false;
        const inBlock = new Set();
        for (const c of claims) { const op = outpointOf(c.txid, c.vout); if (inBlock.has(op)) return false; inBlock.add(op); const at = claimed.get(op); if (at !== undefined && at !== height) return false; }
        for (const op of inBlock) claimed.set(op, height);
        return true;
      },
      // the kernel's rule, plus the paid claims: coinbase value <= subsidy (0) + fees + claims
      'btc:rule-blockctx-coinbase-amount': ({ block, height, spending }) => {
        if (spending.valueUnresolved > 0) return null;
        const cb = block.transactions[0]; const { claims, errors } = parseClaims(cb); if (errors.length) return false;
        const paid = claims.reduce((s, c) => s + c.payout.value, 0);
        return cb.outputs.reduce((s, o) => s + o.value, 0) <= blocks.subsidy(height) + spending.fees + paid;
      },
    } });
    blocks.registerChecks({ block: {
      'sidestr:rule-block-signature': ({ block }) => {
        if (!interpreter) return null;
        const sol = solutionOf(block);
        if (!sol) return false;
        const data = blockData({ codec, hash }, block);
        const { toSign, prevout } = virtualTxs({ codec }, data, params.sidestrChallenge, sol.witness);
        const v = interpreter.verifyInput(toSign, 0, prevout, [prevout], null);
        return v.ok === true;
      },
    } });
  },
});
