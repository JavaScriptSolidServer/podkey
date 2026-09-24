// The rules a chain document names (SPEC 12): `"rules": ["assets", "pool"]`. A validator without
// one of them refuses the chain. Both Node and browsers import this.
import { assetsOverlay } from './assets.mjs';
import { poolOverlay } from './pool.mjs';
import { evmOverlay } from './evm.mjs';
import { parseClaims } from '../overlay.mjs';
export const KNOWN = ['assets', 'pool', 'evm'];
export function rulesFor(chain) {
  const names = chain.rules ?? []; for (const n of names) if (!KNOWN.includes(n)) throw new Error(`chain ${chain.id} names rule "${n}", which this validator does not have`);
  if (names.includes('pool') && !names.includes('assets')) throw new Error('the pool rule needs the assets rule');
  const out = { overlays: [], assets: null, pool: null, evm: null }; if (!names.length) return out;
  if (names.includes('evm')) out.evm = evmOverlay(chain, { claimsOf: (cb) => parseClaims(cb).claims.reduce((s, c) => s + c.payout.value, 0) });
  const pools = new Map(); out.assets = assetsOverlay(chain, { pools: names.includes('pool') ? pools : null });
  if (names.includes('pool')) out.pool = poolOverlay(chain, { assets: out.assets, pools });
  out.overlays = [out.assets, out.pool, out.evm].filter(Boolean); return out;
}
