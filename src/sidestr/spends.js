/**
 * Podkey - the life of one sidestr spend request, in the background
 *
 * A page asks (SIDESTR_SIGN_TRANSACTION). The background checks the request's
 * shape, makes sure the key is unlocked, and opens the spend window
 * (popup/spend.html), which reads and validates the chain, reviews the
 * transaction and shows it. The window asks for the request
 * (SIDESTR_REQUEST), for signatures over the sighashes it computed
 * (SIDESTR_SIGN_DIGESTS, once) and reports the outcome (SIDESTR_DONE). The
 * key never leaves the background; the window never sees it.
 *
 * Every spend opens the window: trust given to an origin for events does not
 * extend to spends. Closing the window rejects; so does silence.
 *
 * Dependencies are passed in so Node can test this without chrome.*.
 */

import { SpendError, checkRequest } from './request.js';

/** The window closes itself with a rejection after this long. */
export const SPEND_WINDOW_MS = 4 * 60 * 1000;
/** At most this many inputs are signed in one request. */
export const MAX_INPUTS = 500;

export function createSpends ({ ensureUnlocked, getKeypair, signSighashes, openWindow, now = () => Date.now(), setTimer = setTimeout, clearTimer = clearTimeout, randomId = () => crypto.randomUUID() }) {
  const pending = new Map(); // id -> { origin, chain, tx, pub, windowId, signed, settle }

  function settle (id, outcome) {
    const p = pending.get(id); if (!p) return false;
    pending.delete(id); clearTimer(p.timer); p.settle(outcome); return true;
  }

  /** From a page, via the content script. Resolves { tx, txid } or rejects with a SpendError. */
  async function request ({ chain, tx }, origin) {
    const req = checkRequest({ chain, tx });
    if (typeof origin !== 'string' || !origin) throw new SpendError('invalid', 'No origin for this request');
    try { await ensureUnlocked(); } catch (e) { throw new SpendError('unavailable', e.message); }
    const keypair = await getKeypair();
    if (!keypair || !/^[0-9a-f]{64}$/.test(keypair.publicKey ?? '')) throw new SpendError('unavailable', 'No key in Podkey');
    const id = randomId();
    return new Promise((resolve, reject) => {
      const entry = {
        origin, chain: req.chain, tx: req.tx, pub: keypair.publicKey, windowId: null, signed: false, opened: now(),
        settle: (o) => (o.error ? reject(o.error) : resolve(o.result))
      };
      entry.timer = setTimer(() => settle(id, { error: new SpendError('rejected', 'The spend window timed out') }), SPEND_WINDOW_MS + 15_000);
      pending.set(id, entry);
      Promise.resolve(openWindow(id)).then((windowId) => { if (pending.has(id)) entry.windowId = windowId ?? null; })
        .catch((e) => settle(id, { error: new SpendError('unavailable', `Could not open the spend window: ${e.message}`) }));
    });
  }

  /** From the spend window: what it is to review. */
  function describe (id) {
    const p = pending.get(id); if (!p) throw new SpendError('unavailable', 'This spend request is no longer open');
    return { origin: p.origin, chain: p.chain, tx: p.tx, pub: p.pub, expiresAt: p.opened + SPEND_WINDOW_MS };
  }

  /** From the spend window, after the person confirmed: sign its sighashes, once. */
  async function signDigests (id, digests) {
    const p = pending.get(id); if (!p) throw new SpendError('unavailable', 'This spend request is no longer open');
    if (p.signed) throw new SpendError('invalid', 'This spend has already been signed');
    if (!Array.isArray(digests) || digests.length < 1 || digests.length > MAX_INPUTS) throw new SpendError('invalid', 'One sighash per input');
    p.signed = true;
    const keypair = await getKeypair();
    if (!keypair || keypair.publicKey !== p.pub) throw new SpendError('unavailable', 'The key changed while the spend was open');
    return { signatures: signSighashes(digests, keypair.privateKey) };
  }

  /** From the spend window: the outcome. `result` is { tx, txid }; `error` is { code, message }. */
  function done (id, { result, error } = {}) {
    if (result && typeof result.tx === 'string' && /^[0-9a-f]{64}$/.test(result.txid ?? '')) {
      const p = pending.get(id);
      if (!p?.signed) return settle(id, { error: new SpendError('unavailable', 'A result arrived for a spend that was never signed') });
      return settle(id, { result: { tx: result.tx, txid: result.txid } });
    }
    return settle(id, { error: new SpendError(error?.code ?? 'rejected', error?.message ?? 'You rejected the spend') });
  }

  /** A window closed: a spend still open in it is rejected. */
  function windowClosed (windowId) {
    for (const [id, p] of pending) if (p.windowId !== null && p.windowId === windowId) settle(id, { error: new SpendError('rejected', 'The spend window was closed') });
  }

  return { request, describe, signDigests, done, windowClosed, pending };
}
