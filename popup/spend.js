/**
 * Podkey - sidestr spend window (sidestr/spec proposals/browser-signer.md)
 *
 * Opened by the background for one spend request. Reads and validates the
 * chain itself, reviews the page's transaction against the person's own
 * coins, shows what leaves the wallet and where it goes, and asks. On Sign it
 * sends the sighashes it computed to the background, which holds the key,
 * then checks the signatures and hands the signed transaction back.
 *
 * Everything shown that came from a page or a relay is written with
 * textContent, never innerHTML.
 */

import * as core from '../src/sidestr/core.js';
import * as settings from '../src/sidestr/settings.js';

const storage = chrome.storage.local;
const cache = settings.cacheStore(storage);
const PROFILE_KIND = 0;
const $ = (id) => document.getElementById(id);
const id = new URLSearchParams(location.search).get('id');

const send = async (message) => {
  const r = await chrome.runtime.sendMessage(message);
  if (r && r.error) throw Object.assign(new Error(r.error), { code: r.code });
  return r;
};

// ---- outcome, exactly once ------------------------------------------------

let finished = false;
function finishWith (outcome) {
  if (finished) return;
  finished = true;
  clearInterval(keepalive);
  send({ type: 'SIDESTR_DONE', id, ...outcome }).catch(() => {});
}
// Closing the window is a rejection (the background also sees the window go).
window.addEventListener('beforeunload', () => finishWith({ error: { code: 'rejected', message: 'You closed the spend window' } }));
// Keep the service worker awake while the person reads.
const keepalive = setInterval(() => send({ type: 'SIDESTR_KEEPALIVE', id }).catch(() => {}), 20_000);

// ---- small formatters -----------------------------------------------------

const sats = (n) => `${n.toLocaleString('en-GB')} sat${n === 1 ? '' : 's'}`;
const short = (s, head = 12, tail = 6) => (s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s);
const assetText = (a) => `${core.formatAsset(a.amount, a.decimals)} ${a.ticker}`;
function el (tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function sumAssets (lists) {
  const m = new Map();
  for (const a of lists.flat()) { const k = a.asset; const cur = m.get(k); m.set(k, cur ? { ...cur, amount: cur.amount + a.amount } : { ...a }); }
  return [...m.values()];
}

// ---- steps ----------------------------------------------------------------

function step (which) {
  const order = ['stepFind', 'stepCheck', 'stepReview'];
  const at = order.indexOf(which);
  order.forEach((s, i) => { $(s).className = `step${i < at ? ' done' : i === at ? ' active' : ''}`; });
}

// ---- countdown --------------------------------------------------------------

let counting = false;
function startCountdown (expiresAt) {
  if (counting) return;
  counting = true;
  const total = Math.max(1, expiresAt - Date.now());
  const tick = () => {
    if (finished) return;
    const left = Math.max(0, expiresAt - Date.now());
    const s = Math.ceil(left / 1000);
    $('countdown').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
    $('timeoutBar').style.width = `${((left / total) * 100).toFixed(2)}%`;
    $('timeoutBar').classList.toggle('urgent', s <= 20);
    if (left <= 0) { finishWith({ error: { code: 'rejected', message: 'The spend window timed out' } }); window.close(); return; }
    setTimeout(tick, 250);
  };
  tick();
}

// ---- names, from each key's own profile (kind 0) --------------------------

// Best effort and never blocking: a name is the key's own claim, so the npub
// stays on screen beside it.
function fetchNames (pubkeys, lib, onName) {
  if (!pubkeys.length) return;
  const want = new Set(pubkeys); const best = new Map();
  for (const url of core.RELAYS) {
    let ws; try { ws = new WebSocket(url); } catch { continue; }
    const stop = setTimeout(() => { try { ws.close(); } catch { /* already closed */ } }, 3000);
    ws.onopen = () => ws.send(JSON.stringify(['REQ', 'n', { kinds: [PROFILE_KIND], authors: [...want] }]));
    ws.onmessage = (m) => {
      let msg; try { msg = JSON.parse(m.data); } catch { return; }
      if (msg[0] === 'EOSE') { clearTimeout(stop); try { ws.close(); } catch { /* already closed */ } return; }
      const ev = msg[0] === 'EVENT' ? msg[2] : null;
      if (!ev || ev.kind !== PROFILE_KIND || !want.has(ev.pubkey)) return;
      let ok = false; try { ok = lib.nostr.verifyNostrEvent(ev); } catch { /* malformed: not ok */ }
      if (!ok || (best.get(ev.pubkey)?.created_at ?? 0) >= ev.created_at) return;
      best.set(ev.pubkey, ev);
      let p; try { p = JSON.parse(ev.content); } catch { return; }
      // drop control characters and the invisible and bidi marks a name could hide behind
      // eslint-disable-next-line no-control-regex
      const name = String(p?.display_name || p?.name || '').replace(/[\u0000-\u001f\u200b-\u200f\u202a-\u202e]/g, '').trim().slice(0, 48);
      if (name) onName(ev.pubkey, name);
    };
    ws.onerror = () => {};
  }
}

// ---- review ---------------------------------------------------------------

function render ({ req, opened, reviewed, pinned, lib }) {
  const { ex, signer, parent, mirror, mirrorNote } = opened;
  $('loading').hidden = true;
  $('review').hidden = false;

  $('chainId').textContent = ex.chain.id;
  $('network').textContent = parent.mainnet ? parent.label : `Test coins · ${parent.label}`;
  const blocks = ex.tip().height + 1;
  const resumed = opened.fromCache;
  $('chainCheck').textContent = resumed == null
    ? `✓ ${blocks.toLocaleString('en-GB')} blocks checked by Podkey · ${mirrorNote}`
    : `✓ ${(blocks - resumed - 1).toLocaleString('en-GB')} new blocks checked by Podkey, ${(resumed + 1).toLocaleString('en-GB')} from your last visit · ${mirrorNote}`;
  $('signer').textContent = short(signer, 8, 8);
  $('signer').title = signer;
  const pin = $('signerPin');
  if (pinned) { pin.textContent = 'same as before'; pin.className = 'pill safe'; }
  else { pin.textContent = 'first spend here: Podkey will remember it'; pin.className = 'pill warn'; }

  // sending
  const list = $('sending'); list.replaceChildren();
  const nameSlots = new Map();
  const others = reviewed.outputs.filter((o) => o.kind !== 'change' && o.kind !== 'asset-record');
  if (!others.length) list.append(el('li', 'who-sub', 'Nothing goes to anyone else: this only rearranges your own coins.'));
  for (const o of others) {
    const li = el('li'); const who = el('div', 'who'); const amounts = el('div', 'amounts');
    if (o.kind === 'key') {
      const name = el('div', 'who-name', short(o.npub, 14, 8)); name.title = o.npub;
      const sub = el('div', 'who-sub', o.npub); sub.hidden = true;
      who.append(name, sub);
      if (!nameSlots.has(o.pubkey)) nameSlots.set(o.pubkey, []);
      nameSlots.get(o.pubkey).push({ name, sub });
    } else if (o.kind === 'script') {
      who.append(el('div', 'who-name', o.address ? short(o.address, 16, 8) : 'A script'), el('div', 'who-sub', o.address ?? o.script));
    } else if (o.kind === 'pegout') {
      who.append(el('div', 'who-name', 'Peg-out to the parent chain'), el('div', 'who-sub', o.to));
    } else if (o.kind === 'burn') {
      who.append(el('div', 'who-name', 'Burned'), el('div', 'who-sub', o.text ?? o.script));
    } else {
      who.append(el('div', 'who-name', 'Note on the chain'), el('div', 'who-sub', o.text ?? o.script));
    }
    if (o.assets.length) {
      amounts.append(el('div', 'amount-main', o.assets.map(assetText).join(' + ')));
      if (o.value) amounts.append(el('div', 'amount-sub', `+ ${sats(o.value)}`));
    } else if (o.value || o.kind !== 'record') {
      amounts.append(el('div', 'amount-main', sats(o.value)));
    }
    li.append(who, amounts); list.append(li);
  }
  fetchNames([...nameSlots.keys()], lib, (pubkey, nm) => {
    for (const { name, sub } of nameSlots.get(pubkey) ?? []) { name.textContent = nm; sub.hidden = false; }
  });

  // back to you
  const change = reviewed.outputs.filter((o) => o.kind === 'change');
  if (change.length) {
    const back = change.reduce((s, o) => s + o.value, 0);
    const assetsBack = sumAssets(change.map((o) => o.assets));
    $('back').textContent = [sats(back), ...assetsBack.map(assetText)].join(' + ');
    $('backCard').hidden = false;
  }

  // fee and total
  $('fee').textContent = sats(reviewed.fee);
  const leavingSats = reviewed.inSum - change.reduce((s, o) => s + o.value, 0);
  const leavingAssets = sumAssets([...others.map((o) => o.assets), reviewed.destroyed.map((d) => ({ ...d, ...labelOf(reviewed, d.asset) }))]);
  $('total').textContent = [...leavingAssets.map(assetText), sats(leavingSats)].join(' + ');

  if (reviewed.inputs.some((i) => i.carries.length) || others.some((o) => o.assets.length)) {
    $('assetNote').hidden = false;
    $('assetNote').textContent = reviewed.assetMode === 'rule'
      ? `${ex.chain.id} enforces its assets: every node checks these amounts.`
      : `Assets on ${ex.chain.id} are kept by their holders' records; the chain itself does not enforce them. Podkey read them from every block.`;
  }

  // warnings: anything that destroys or burns needs an explicit tick
  const severe = reviewed.warnings.filter((w) => ['destroys', 'breaks', 'burn', 'pegout'].includes(w.kind));
  if (reviewed.warnings.length) {
    $('warnings').hidden = false;
    $('warningList').replaceChildren(...reviewed.warnings.map((w) => el('li', null, w.text)));
    $('ackRow').hidden = !severe.length;
  }

  // details
  $('txid').textContent = reviewed.txid;
  $('inputs').replaceChildren(...reviewed.inputs.map((i) => el('li', null, `${short(i.key, 16, 4)} · ${sats(i.value)}${i.carries.length ? ` · ${i.carries.map(assetText).join(', ')}` : ''}`)));
  const recs = reviewed.outputs.filter((o) => o.kind === 'asset-record');
  $('records').replaceChildren(...(recs.length ? recs.map((o) => el('li', null, o.text)) : [el('li', null, 'none')]));
  $('mirror').textContent = mirror;

  const sign = $('sign');
  const ready = () => { sign.disabled = severe.length > 0 && !$('ack').checked; };
  $('ack').addEventListener('change', ready); ready();
  sign.addEventListener('click', () => doSign({ req, opened, reviewed, pinned, lib }));
}

function labelOf (reviewed, asset) {
  const found = [...reviewed.outputs.flatMap((o) => o.assets), ...reviewed.inputs.flatMap((i) => i.carries)].find((a) => a.asset === asset);
  return found ? { ticker: found.ticker, decimals: found.decimals } : { ticker: `${asset.slice(0, 8)}…`, decimals: 0 };
}

async function doSign ({ req, opened, reviewed, pinned, lib }) {
  $('sign').disabled = true; $('reject').disabled = true;
  $('sign').textContent = 'Signing…';
  try {
    const { signatures } = await send({ type: 'SIDESTR_SIGN_DIGESTS', id, digests: reviewed.sighashes.map((s) => s.digest) });
    const result = core.finish({ ex: opened.ex, lib, reviewed, signatures, pub: req.pub });
    if (!pinned) await settings.pinChain(storage, req.chain, opened.signer);
    finishWith({ result });
    $('review').hidden = true; $('countdownWrap').hidden = true; $('signed').hidden = false;
    setTimeout(() => window.close(), 1200);
  } catch (e) {
    fail(e);
  }
}

// ---- failure --------------------------------------------------------------

const TITLES = {
  'not-yours': 'This spends coins that are not yours',
  unsupported: 'Podkey does not sign for this chain',
  invalid: 'This is not a spend Podkey can read',
  unavailable: 'Podkey could not check this spend',
  rejected: 'Spend rejected'
};

function fail (e) {
  const code = core.CODES.includes(e?.code) ? e.code : 'unavailable';
  const message = e?.message || String(e);
  $('loading').hidden = true; $('review').hidden = true; $('failure').hidden = false;
  $('failureTitle').textContent = TITLES[code];
  $('failureText').textContent = message;
  $('forgetRow').hidden = !(code === 'unsupported' && /different signer/.test(message));
  $('close').onclick = () => { finishWith({ error: { code, message } }); window.close(); };
}

$('forgetAck').addEventListener('change', () => { $('forget').disabled = !$('forgetAck').checked; });
$('forget').addEventListener('click', async () => {
  const req = await send({ type: 'SIDESTR_REQUEST', id });
  await settings.forgetChain(storage, req.chain);
  $('failure').hidden = true; $('loading').hidden = false;
  main();
});

$('reject').addEventListener('click', () => {
  finishWith({ error: { code: 'rejected', message: 'You rejected the spend' } });
  window.close();
});

// ---- opt-in ---------------------------------------------------------------

// Spends are off until the person turns them on. A site that asks while they
// are off gets this, in Podkey's own window, rather than a dead end.
function askToTurnOn () {
  return new Promise((resolve) => {
    $('loading').hidden = true; $('optIn').hidden = false;
    $('optInYes').focus();
    $('optInYes').onclick = () => { $('optIn').hidden = true; $('loading').hidden = false; resolve(true); };
    $('optInNo').onclick = () => resolve(false);
  });
}

// ---- main -----------------------------------------------------------------

// Open the chain, from the saved state where there is one; a saved asset view
// that does not match the explorer's saved state means both are dropped and
// every block is checked again.
async function openWithCache (lib, chainId, pinned) {
  const progress = (m) => { if (/^Checking/.test(m)) step('stepCheck'); };
  let opened = await core.openChain({ lib, chainId, pinned, store: cache, onProgress: progress });
  let view;
  try {
    const raw = opened.fromCache == null ? null : await cache.get(core.assetCacheKey(chainId));
    view = core.assetView(opened.ex, lib, { cached: raw ? JSON.parse(raw) : null });
  } catch (e) {
    if (!(e instanceof core.CacheMismatch) && !(e instanceof SyntaxError)) throw e;
    await settings.clearCaches(storage, chainId);
    opened = await core.openChain({ lib, chainId, pinned, store: cache, onProgress: progress });
    view = core.assetView(opened.ex, lib);
  }
  const saved = core.serializeView(view, opened.ex);
  if (saved && opened.ex.cacheable) await cache.set(core.assetCacheKey(chainId), saved);
  return { opened, view };
}

async function main () {
  try {
    const req = await send({ type: 'SIDESTR_REQUEST', id });
    $('origin').textContent = req.origin;
    $('loadingChain').textContent = req.chain;
    startCountdown(req.expiresAt);
    let s = await settings.load(storage);
    if (!s.enabled) {
      $('optInOrigin').textContent = req.origin;
      if (!(await askToTurnOn())) {
        finishWith({ error: { code: 'unsupported', message: 'Sidechain spends are turned off in Podkey' } });
        window.close();
        return;
      }
      s = await settings.enable(storage);
    }
    step('stepFind');
    const lib = await core.loadLib();
    const pinned = s.chains[req.chain]?.signer ?? null;
    const { opened, view } = await openWithCache(lib, req.chain, pinned);
    step('stepReview');
    const reviewed = core.review({ ex: opened.ex, lib, view, pub: req.pub, txHex: req.tx });
    render({ req, opened, reviewed, pinned, lib });
  } catch (e) {
    fail(e);
  }
}

main();
