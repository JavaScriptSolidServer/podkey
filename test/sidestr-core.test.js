/**
 * Tests for the sidestr spend window's core (src/sidestr/core.js), offline,
 * against the real vendored engine: the kernel decodes and hashes, the spec
 * lib computes BIP 341 sighashes and checks signatures, and the assets rule
 * reads records. Only the chain's block history is synthetic.
 *
 * What is proved: a spend of the person's own coins reviews, signs through
 * Podkey's own signing path, and verifies as a validator would; anything else
 * is refused with the proposal's codes; a transaction that would destroy an
 * asset its inputs carry says so.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as secp256k1 from '@noble/secp256k1';
import * as core from '../src/sidestr/core.js';
import { signSighashes, getPublicKey } from '../src/crypto.js';

const loadJson = async (u) => JSON.parse(await readFile(new URL(u), 'utf8'));
const chain = JSON.parse(await readFile(new URL('./fixtures/sidestr-dreamlab.chain.json', import.meta.url), 'utf8'));

let lib, engine;
const hex = (b) => Buffer.from(b).toString('hex');
const secret = hex(secp256k1.utils.randomSecretKey());
const pub = getPublicKey(secret);
const me = `5120${pub}`;
const stranger = `5120${'ab'.repeat(32)}`;

/** A fake explorer: the real kernel over a synthetic, already-validated history. */
function makeEx ({ utxo = [], blocks = [], height = 200, rules = { overlays: [], assets: null } } = {}) {
  return {
    k: engine.k, hash: engine.hash, chain, rules,
    utxo: new Map(utxo),
    blocks,
    tip: () => ({ height })
  };
}
const coin = (value, script = me, { height = 10, coinbase = false } = {}) => ({ output: { value, scriptPubKey: script }, height, coinbase, outpoint: {} });
const input = (txid, vout = 0) => ({ prevout: { txid, vout }, scriptSig: '', sequence: 0xfffffffd });
const T = (n) => String(n).repeat(64).slice(0, 64);
const encode = (tx) => engine.k.codec.encodeHex('Transaction', { version: 2, lockTime: 0, witness: [], ...tx });
const emptyView = () => core.assetView(makeEx(), lib);

before(async () => {
  lib = await core.loadLib();
  engine = await lib.explorer.loadEngine(chain, { loadJson });
});

describe('checkRequest', () => {
  it('takes a chain id and hex, lower-casing the hex', () => {
    assert.deepEqual(core.checkRequest({ chain: 'sidestr:dreamlab', tx: 'AB00' }), { chain: 'sidestr:dreamlab', tx: 'ab00' });
  });
  it('refuses a bad chain id, odd or non-hex tx, and oversized tx as invalid', () => {
    for (const bad of [{ chain: 'dreamlab', tx: '00' }, { chain: 'sidestr:', tx: '00' }, { chain: 'sidestr:x', tx: '0' }, { chain: 'sidestr:x', tx: 'zz' }, { chain: 'sidestr:x', tx: '00'.repeat(core.MAX_TX_HEX) }, {}]) {
      assert.throws(() => core.checkRequest(bad), (e) => e.code === 'invalid');
    }
  });
});

describe('review and finish: the whole signing path', () => {
  it('reviews a spend of your own coin, signs it with Podkey\'s key, and it verifies', () => {
    const ex = makeEx({ utxo: [[`${T(1)}:0`, coin(10_000)]] });
    const txHex = encode({ inputs: [input(T(1))], outputs: [{ value: 3_000, scriptPubKey: stranger }, { value: 6_800, scriptPubKey: me }] });
    const r = core.review({ ex, lib, view: emptyView(), pub, txHex });
    assert.equal(r.fee, 200);
    assert.deepEqual(r.outputs.map((o) => o.kind), ['key', 'change']);
    assert.match(r.outputs[0].npub, /^npub1/);
    assert.equal(r.toOthers, 3_000);
    assert.equal(r.warnings.length, 0);
    assert.equal(r.sighashes.length, 1);
    assert.equal(r.sighashes[0].ht, 0x01, 'beside stock Bitcoin: BIP 341, SIGHASH_ALL');

    const signatures = signSighashes(r.sighashes.map((s) => s.digest), secret);
    const out = core.finish({ ex, lib, reviewed: r, signatures, pub });
    assert.equal(out.txid, r.txid, 'a witness does not change the txid');
    const signed = engine.k.codec.decode('Transaction', out.tx);
    assert.equal(signed.witness[0][0].length, 130, '64-byte signature plus the hash type');
    // an independent implementation (the engine's own secp256k1) agrees
    assert.equal(lib.txsign.verifyKeyPath({ k: engine.k, hash: engine.hash, secp: lib.secp }, signed, r.prevouts, pub), true);
  });

  it('replaces any witness the page sent', () => {
    const ex = makeEx({ utxo: [[`${T(1)}:0`, coin(10_000)]] });
    const txHex = encode({ inputs: [input(T(1))], outputs: [{ value: 9_000, scriptPubKey: stranger }], witness: [['ff'.repeat(65)]] });
    const r = core.review({ ex, lib, view: emptyView(), pub, txHex });
    assert.deepEqual(r.tx.witness, []);
  });

  it('refuses a signature that is not over the reviewed sighash', () => {
    const ex = makeEx({ utxo: [[`${T(1)}:0`, coin(10_000)]] });
    const r = core.review({ ex, lib, view: emptyView(), pub, txHex: encode({ inputs: [input(T(1))], outputs: [{ value: 9_000, scriptPubKey: stranger }] }) });
    const wrong = signSighashes(['00'.repeat(32)], secret);
    assert.throws(() => core.finish({ ex, lib, reviewed: r, signatures: wrong, pub }), /did not verify/);
    assert.throws(() => core.finish({ ex, lib, reviewed: r, signatures: [], pub }), /one signature per input/);
  });
});

describe('review refuses what is not yours', () => {
  const view = () => emptyView();
  it('a coin paying someone else', () => {
    const ex = makeEx({ utxo: [[`${T(1)}:0`, coin(10_000, stranger)]] });
    assert.throws(() => core.review({ ex, lib, view: view(), pub, txHex: encode({ inputs: [input(T(1))], outputs: [{ value: 9_000, scriptPubKey: me }] }) }), (e) => e.code === 'not-yours');
  });
  it('a coin Podkey cannot see (spent, unconfirmed or invented)', () => {
    const ex = makeEx();
    assert.throws(() => core.review({ ex, lib, view: view(), pub, txHex: encode({ inputs: [input(T(2))], outputs: [{ value: 1, scriptPubKey: me }] }) }), (e) => e.code === 'not-yours');
  });
  it('an immature block reward', () => {
    const ex = makeEx({ utxo: [[`${T(1)}:0`, coin(10_000, me, { height: 150, coinbase: true })]], height: 200 });
    assert.throws(() => core.review({ ex, lib, view: view(), pub, txHex: encode({ inputs: [input(T(1))], outputs: [{ value: 9_000, scriptPubKey: me }] }) }), (e) => e.code === 'not-yours' && /not mature/.test(e.message));
  });
  it('the same coin twice, outputs over inputs, and junk as invalid', () => {
    const ex = makeEx({ utxo: [[`${T(1)}:0`, coin(10_000)]] });
    assert.throws(() => core.review({ ex, lib, view: view(), pub, txHex: encode({ inputs: [input(T(1)), input(T(1))], outputs: [{ value: 1, scriptPubKey: me }] }) }), (e) => e.code === 'invalid');
    assert.throws(() => core.review({ ex, lib, view: view(), pub, txHex: encode({ inputs: [input(T(1))], outputs: [{ value: 20_000, scriptPubKey: me }] }) }), (e) => e.code === 'invalid');
    assert.throws(() => core.review({ ex, lib, view: view(), pub, txHex: 'deadbeef' }), (e) => e.code === 'invalid');
  });
});

describe('warnings', () => {
  it('a burn, a peg-out and a large fee are all flagged', () => {
    const ex = makeEx({ utxo: [[`${T(1)}:0`, coin(50_000)]] });
    const pegout = lib.records.recordScript(`pegout:${'00'.repeat(2)}14${'11'.repeat(20)}`);
    const txHex = encode({ inputs: [input(T(1))], outputs: [{ value: 10_000, scriptPubKey: pegout }, { value: 1_000, scriptPubKey: lib.records.recordScript('gone') }, { value: 100, scriptPubKey: stranger }] });
    const r = core.review({ ex, lib, view: emptyView(), pub, txHex });
    assert.deepEqual(r.warnings.map((w) => w.kind).sort(), ['burn', 'fee', 'pegout']);
  });
});

describe('assets (SPEC 12)', () => {
  // history: an issue of 1000 DREAM onto one of my coins, then a transfer that
  // breaks the rule (assigns more than it carries), whose outputs must carry nothing
  function history () {
    const issue = { version: 2, lockTime: 0, witness: [], inputs: [input(T(5))], outputs: [{ value: 330, scriptPubKey: me }, { value: 0, scriptPubKey: lib.records.recordScript('issue:DREAM:0') }, { value: 0, scriptPubKey: lib.records.recordScript('tally:self:0=1000') }] };
    const issueId = engine.k.codec.txid(issue);
    const other = { version: 2, lockTime: 0, witness: [], inputs: [input(T(6))], outputs: [{ value: 330, scriptPubKey: me }, { value: 0, scriptPubKey: lib.records.recordScript(`tally:${issueId}:0=5`) }] };
    const otherId = engine.k.codec.txid(other);
    const blocks = [{ block: { transactions: [{}, issue] }, txids: ['cb0', issueId] }, { block: { transactions: [{}, other] }, txids: ['cb1', otherId] }];
    const utxo = [[`${issueId}:0`, coin(330)], [`${otherId}:0`, coin(330)], [`${T(7)}:0`, coin(20_000)]];
    return { ex: makeEx({ utxo, blocks }), issueId, otherId };
  }

  it('the holders\' view reads the issue and refuses to create from nothing', () => {
    const { ex, issueId, otherId } = history();
    const view = core.assetView(ex, lib);
    assert.equal(view.mode, 'view');
    assert.equal(view.issued.get(issueId).ticker, 'DREAM');
    assert.equal(view.carried.get(`${issueId}:0`).get(issueId), 1000);
    assert.equal(view.carried.has(`${otherId}:0`), false, 'a transaction that breaks the rule carries nothing');
  });

  it('a transfer that tallies DREAM onward shows it, with nothing destroyed', () => {
    const { ex, issueId } = history();
    const view = core.assetView(ex, lib);
    const txHex = encode({ inputs: [input(issueId), input(T(7))], outputs: [{ value: 330, scriptPubKey: stranger }, { value: 330, scriptPubKey: me }, { value: 0, scriptPubKey: lib.records.recordScript(`tally:${issueId}:0=100,1=900`) }, { value: 19_000, scriptPubKey: me }] });
    const r = core.review({ ex, lib, view, pub, txHex });
    assert.deepEqual(r.outputs[0].assets.map((a) => [a.ticker, a.amount]), [['DREAM', 100]]);
    assert.deepEqual(r.outputs[1].assets.map((a) => [a.ticker, a.amount]), [['DREAM', 900]]);
    assert.equal(r.destroyed.length, 0);
    assert.equal(r.warnings.length, 0);
  });

  it('a "sats only" spend that sweeps a DREAM coin is flagged as destroying it', () => {
    const { ex, issueId } = history();
    const view = core.assetView(ex, lib);
    const txHex = encode({ inputs: [input(issueId), input(T(7))], outputs: [{ value: 20_000, scriptPubKey: stranger }] });
    const r = core.review({ ex, lib, view, pub, txHex });
    assert.deepEqual(r.destroyed, [{ asset: issueId, amount: 1000 }]);
    assert.ok(r.warnings.some((w) => w.kind === 'destroys' && /1,000 DREAM/.test(w.text)));
  });

  it('on a chain that enforces the rule, a breaking transaction is refused as invalid', () => {
    const { ex, issueId } = history();
    const view = core.assetView(ex, lib);
    const enforced = { ...view, mode: 'rule' };
    const txHex = encode({ inputs: [input(issueId)], outputs: [{ value: 330, scriptPubKey: stranger }, { value: 0, scriptPubKey: lib.records.recordScript(`tally:${issueId}:0=5000`) }] });
    assert.throws(() => core.review({ ex, lib, view: enforced, pub, txHex }), (e) => e.code === 'invalid');
  });
});

describe('formatAsset', () => {
  it('formats whole and decimal units', () => {
    assert.equal(core.formatAsset(1_000_000, 0), '1,000,000');
    assert.equal(core.formatAsset(150, 2), '1.50');
    assert.equal(core.formatAsset(5, 2), '0.05');
  });
});
