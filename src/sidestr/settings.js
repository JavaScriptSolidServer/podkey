/**
 * Podkey - sidestr settings: opt-in, the chains in use, and the cache
 *
 * Sidechain spends are off until the person turns them on, either in the
 * popup's settings or in the spend window when a site first asks. Each chain
 * used is listed with the signer Podkey settled on the first time (a chain id
 * is a name, not a proof), and its validated state is cached so the next spend
 * checks only the blocks since. Forgetting a chain, or turning spends off,
 * drops its pin and its cache.
 *
 * `storage` is chrome.storage.local, or anything with the same
 * get/set/remove shape, so Node can test this.
 */

/** The settings: { enabled, chains: { [chain id]: { signer, addedAt } } }. */
export const SETTINGS_KEY = 'podkey_sidestr';
/** 0.0.9 stored pins here, before spends were opt-in. */
export const LEGACY_PINS_KEY = 'podkey_sidestr_signers';
/** Every cache entry's storage key starts with this. */
export const CACHE_PREFIX = 'podkey_sidestr_cache:';

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * The settings from what storage holds. Pins from 0.0.9 carry over, and count
 * as having turned spends on: the person already approved a spend there.
 */
export function normalize (raw, legacyPins) {
  const chains = {};
  for (const [id, entry] of Object.entries(raw?.chains ?? {})) {
    if (HEX64.test(entry?.signer ?? '')) chains[id] = { signer: entry.signer, addedAt: Number(entry.addedAt) || 0 };
  }
  let enabled = raw?.enabled === true;
  for (const [id, signer] of Object.entries(legacyPins ?? {})) {
    if (!chains[id] && HEX64.test(signer ?? '')) { chains[id] = { signer, addedAt: 0 }; enabled = true; }
  }
  return { enabled, chains };
}

export async function load (storage) {
  const got = await storage.get([SETTINGS_KEY, LEGACY_PINS_KEY]);
  return normalize(got[SETTINGS_KEY], got[LEGACY_PINS_KEY]);
}

async function save (storage, settings) {
  await storage.set({ [SETTINGS_KEY]: settings });
  await storage.remove(LEGACY_PINS_KEY);
  return settings;
}

/** Turn sidechain spends on. */
export async function enable (storage) {
  const s = await load(storage);
  return save(storage, { ...s, enabled: true });
}

/** Turn sidechain spends off: every pin and every cache goes too. */
export async function disable (storage) {
  await clearCaches(storage);
  return save(storage, { enabled: false, chains: {} });
}

/** Remember the signer Podkey settled on for a chain. */
export async function pinChain (storage, chainId, signer, now = Date.now()) {
  if (!HEX64.test(signer ?? '')) throw new Error('A signer is a 64-hex key');
  const s = await load(storage);
  return save(storage, { ...s, chains: { ...s.chains, [chainId]: { signer, addedAt: s.chains[chainId]?.addedAt || now } } });
}

/** Forget a chain: its pinned signer and its cache. */
export async function forgetChain (storage, chainId) {
  await clearCaches(storage, chainId);
  const s = await load(storage);
  const chains = { ...s.chains }; delete chains[chainId];
  return save(storage, { ...s, chains });
}

/** Drop the cache for one chain, or for every chain. */
export async function clearCaches (storage, chainId = null) {
  const all = await storage.get(null);
  const keys = Object.keys(all ?? {}).filter((k) => k.startsWith(CACHE_PREFIX) && (chainId === null || k.endsWith(`:${chainId}`)));
  if (keys.length) await storage.remove(keys);
}

/**
 * The { get, set, delete } store the explorer and the asset view keep their
 * validated state in, namespaced under CACHE_PREFIX. A failed write (quota)
 * only means the next spend validates from the start.
 */
export function cacheStore (storage) {
  return {
    async get (key) { const k = CACHE_PREFIX + key; return (await storage.get(k))[k] ?? null; },
    async set (key, value) { try { await storage.set({ [CACHE_PREFIX + key]: value }); } catch { /* quota: validate in full next time */ } },
    async delete (key) { await storage.remove(CACHE_PREFIX + key); }
  };
}
