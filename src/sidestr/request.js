/**
 * Podkey - the shape of a sidestr spend request (sidestr/spec proposals/browser-signer.md)
 *
 * Shared by the background service worker, which checks a page's request
 * before opening the spend window, and by the window itself. No imports, so
 * the service worker bundle stays free of the chain engine.
 */

/** Error codes the page sees, per the proposal. */
export const CODES = ['rejected', 'unsupported', 'not-yours', 'invalid', 'unavailable'];

/** An error with one of CODES, for the page. */
export class SpendError extends Error {
  constructor (code, message) {
    super(message);
    this.name = 'SpendError';
    this.code = CODES.includes(code) ? code : 'unavailable';
  }
}

const CHAIN_ID = /^sidestr:[a-z0-9][a-z0-9._-]{0,63}$/;
const HEX = /^(?:[0-9a-f]{2})+$/;
/** The largest transaction a page may ask about, in hex characters (200 kB). */
export const MAX_TX_HEX = 400_000;

/** Check a request's shape before anything is fetched. Throws a SpendError. */
export function checkRequest ({ chain, tx } = {}) {
  if (typeof chain !== 'string' || !CHAIN_ID.test(chain)) throw new SpendError('invalid', 'chain must be a sidestr chain id, such as sidestr:dreamlab');
  if (typeof tx !== 'string') throw new SpendError('invalid', 'tx must be the transaction as hex');
  const hex = tx.trim().toLowerCase();
  if (!hex || hex.length > MAX_TX_HEX || !HEX.test(hex)) throw new SpendError('invalid', 'tx must be the transaction as hex, at most 200 kB');
  return { chain, tx: hex };
}
