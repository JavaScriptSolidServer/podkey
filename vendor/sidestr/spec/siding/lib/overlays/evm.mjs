// Podkey stub for siding/lib/overlays/evm.mjs. The EVM rule imports ethereumjs
// from jsdelivr when it starts, and a Manifest V3 extension may not run code
// from the network, so a chain that names the rule is refused as unsupported
// until the rule is vendored too. See scripts/vendor-sidestr.js.
export function evmOverlay (chain) {
  const e = new Error(`${chain?.id ?? 'this chain'} names the evm rule, which Podkey cannot run yet`);
  e.code = 'unsupported';
  throw e;
}
