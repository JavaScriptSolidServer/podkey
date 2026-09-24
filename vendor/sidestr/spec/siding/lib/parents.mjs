// The parents a chain can sit beside (SPEC 3.2): a short alias per chain, the long kernel id it
// resolves to, and the header family the chain inherits. Browsers and Node alike; no imports.
// Old spellings (the kernel's long ids) stay accepted, so no running chain's document changes.
// `mainnet` picks the key and address encodings a node expects (WIF 0x80 vs 0xef).
export const PARENTS = {
  btc:   { network: 'btc:mainnet',          label: 'Bitcoin mainnet',          family: 'stock',   pow: 'sha256d', mainnet: true,
           genesis: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f' },
  tbtc4: { network: 'btc:testnet4',         label: 'Bitcoin testnet4',         family: 'stock',   pow: 'sha256d', mainnet: false,
           genesis: '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043' },
  xbt:   { network: 'btc:mainnet-blake2b',  label: 'BLAKE2b mainnet (Knots)',  family: 'blake2b', pow: 'blake2b', mainnet: true,
           genesis: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
           fork: { height: 961640, hash: '0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb' } },
  txbt4: { network: 'btc:testnet4-blake2b', label: 'BLAKE2b testnet4 (Knots)', family: 'blake2b', pow: 'blake2b', mainnet: false,
           genesis: '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043',
           fork: { height: 150308, hash: '000000000000b9d1b7e1bb0e77215ee92c6ef7ec8f4473e23908380649e779b6' } },
  ltc:   { network: null, label: 'Litecoin mainnet', family: 'stock', pow: 'scrypt',   mainnet: true, reserved: true },
  vtc:   { network: null, label: 'Vertcoin mainnet', family: 'stock', pow: 'verthash', mainnet: true, reserved: true },
};
const LONG = Object.fromEntries(Object.entries(PARENTS).filter(([, p]) => p.network).map(([a, p]) => [p.network, a]));

// alias or long id → the alias; null when neither
export function parentAlias(id) { if (typeof id !== 'string') return null; if (Object.hasOwn(PARENTS, id)) return id; return Object.hasOwn(LONG, id) ? LONG[id] : null; }
// alias or long id → { alias, ...entry }; throws for a reserved or unknown parent
export function resolveParent(id) {
  const alias = parentAlias(id); if (!alias) throw new Error(`unknown parent "${id}": one of ${Object.keys(PARENTS).join(', ')} (SPEC 3.2)`);
  const p = PARENTS[alias]; if (p.reserved) throw new Error(`parent "${alias}" (${p.label}) is reserved: no validator carries its rules yet (SPEC 3.2)`);
  return { alias, ...p };
}
export const isBlake2b = (id) => resolveParent(id).family === 'blake2b';
