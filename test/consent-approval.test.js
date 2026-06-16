/**
 * Tests for the per-origin consent gate / signing-approval flow.
 *
 * background.js exports nothing and wires its handlers onto chrome.runtime at
 * import time, so these tests drive it exactly the way the real extension does:
 * mock `chrome`, import the module to capture the onMessage listener, then send
 * the same messages the content script and approve popup would send.
 *
 * Covered (consent contract, security/signing-approval-ui #20):
 *   - approve resolves the pending request with the result
 *   - deny rejects the request ("User denied ...")
 *   - the 60s timeout auto-denies
 *   - APPROVE_SIGNING with approved:false (popup beforeunload = deny) rejects
 *   - trusted-origin auto-path: a trusted origin signs ANY event kind with no
 *     prompt (general NIP-07 signer); an untrusted origin always prompts, and
 *     approving it establishes revocable trust
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';

// --- chrome mock (session + local areas, like storage.test.js) ----------------
function makeArea (store) {
  return {
    get: async (keys) => {
      const result = {};
      if (Array.isArray(keys)) {
        keys.forEach((k) => { result[k] = store[k]; });
      } else if (keys) {
        Object.keys(keys).forEach((k) => { result[k] = store[k] ?? keys[k]; });
      } else {
        return { ...store };
      }
      return result;
    },
    set: async (items) => { Object.assign(store, items); },
    remove: async (keys) => {
      (Array.isArray(keys) ? keys : [keys]).forEach((k) => delete store[k]);
    }
  };
}

const stores = { local: {}, session: {} };
const windowsCreated = [];
const captured = { onMessage: null };

global.chrome = {
  runtime: {
    onInstalled: { addListener: () => {} },
    onMessage: { addListener: (fn) => { captured.onMessage = fn; } },
    lastError: null
  },
  windows: {
    create: (opts) => { windowsCreated.push(opts); return Promise.resolve({ id: windowsCreated.length }); }
  },
  storage: {
    local: makeArea(stores.local),
    session: makeArea(stores.session)
  }
};

// Import background once (captures the onMessage listener). Storage helpers are
// imported separately for seeding; they share the same chrome mock instance.
await import('../src/background.js');
const { generateKeypair } = await import('../src/crypto.js');
const { storeKeypair, addTrustedOrigin, setAutoSign } = await import('../src/storage.js');

const onMessage = captured.onMessage;

/**
 * Drain the microtask queue. handleMessage awaits several storage reads before
 * it reaches showPermissionPrompt / chrome.windows.create; one setImmediate
 * turn flushes that chain deterministically (and is not affected by the faked
 * setTimeout used in the timeout tests).
 */
const flush = () => new Promise((resolve) => setImmediate(resolve));

/** Send a message to the background and return a promise of sendResponse(). */
function send (message) {
  return new Promise((resolve) => { onMessage(message, {}, resolve); });
}

/** Read the requestId out of the most recently opened approval popup URL. */
function lastRequestId () {
  const last = windowsCreated[windowsCreated.length - 1];
  // url is `popup/approve.html?id=...&origin=...` — parse against a dummy base
  return new URL('https://x/' + last.url).searchParams.get('id');
}

/** Resolve a pending prompt by sending the popup's APPROVE_SIGNING message. */
function respond (requestId, approved) {
  onMessage({ type: 'APPROVE_SIGNING', requestId, approved }, {}, () => {});
}

const SOLID_EVENT = { kind: 27235, created_at: 1700000000, tags: [['u', 'https://pod.test/']], content: '' };
const NOTE_EVENT = { kind: 1, created_at: 1700000000, tags: [], content: 'gm' };

describe('consent gate / approval flow', () => {
  let keypair;

  beforeEach(async () => {
    // Reset storage and the record of opened windows before every test.
    for (const k of Object.keys(stores.local)) delete stores.local[k];
    for (const k of Object.keys(stores.session)) delete stores.session[k];
    windowsCreated.length = 0;
    keypair = await generateKeypair();
    await storeKeypair(keypair.privateKey, keypair.publicKey);
  });

  afterEach(() => { mock.timers.reset(); });

  it('opens an approval popup for an untrusted origin (does not auto-resolve)', async () => {
    const pending = send({ type: 'GET_PUBLIC_KEY', origin: 'https://untrusted.test' });
    // Let the handler reach showPermissionPrompt / chrome.windows.create.
    await flush();
    assert.equal(windowsCreated.length, 1, 'exactly one approval popup should open');
    const url = windowsCreated[0].url;
    assert.match(url, /^popup\/approve\.html\?/);
    const params = new URL('https://x/' + url).searchParams;
    assert.equal(params.get('origin'), 'https://untrusted.test');
    assert.equal(params.get('action'), 'read your public key');
    assert.ok(params.get('id'), 'a requestId must be present');
    // Clean up the dangling promise so the test runner doesn't hang.
    respond(params.get('id'), true);
    await pending;
  });

  it('approve resolves the pending request with the public key', async () => {
    const pending = send({ type: 'GET_PUBLIC_KEY', origin: 'https://app.test' });
    await flush();
    respond(lastRequestId(), true);
    const result = await pending;
    assert.equal(result, keypair.publicKey);
  });

  it('deny rejects the request with "User denied permission"', async () => {
    const pending = send({ type: 'GET_PUBLIC_KEY', origin: 'https://app.test' });
    await flush();
    respond(lastRequestId(), false);
    const result = await pending;
    assert.deepEqual(result, { error: 'User denied permission' });
  });

  it('APPROVE_SIGNING approved:false (popup beforeunload = deny) rejects signing', async () => {
    const pending = send({ type: 'SIGN_EVENT', event: NOTE_EVENT, origin: 'https://app.test' });
    await flush();
    // The approve popup sends {approved:false} on window beforeunload (closing
    // the window without choosing = deny). Same wire message, approved:false.
    respond(lastRequestId(), false);
    const result = await pending;
    assert.deepEqual(result, { error: 'User denied signing' });
  });

  it('the 60s timeout auto-denies when the popup never responds', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const pending = send({ type: 'GET_PUBLIC_KEY', origin: 'https://slow.test' });
    await flush();
    assert.equal(windowsCreated.length, 1, 'popup opened, awaiting a decision');
    // No APPROVE_SIGNING arrives. Advance just past the 60s auto-deny.
    mock.timers.tick(60001);
    const result = await pending;
    assert.deepEqual(result, { error: 'User denied permission' });
  });

  it('does NOT auto-deny before 60s elapse', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const pending = send({ type: 'GET_PUBLIC_KEY', origin: 'https://app.test' });
    await flush();
    mock.timers.tick(59999); // one ms short of the deadline
    // Still pending — a late approval must win the race.
    respond(lastRequestId(), true);
    const result = await pending;
    assert.equal(result, keypair.publicKey);
  });

  it('a late APPROVE_SIGNING after timeout is ignored (entry already deleted)', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const pending = send({ type: 'GET_PUBLIC_KEY', origin: 'https://app.test' });
    await flush();
    const id = lastRequestId();
    mock.timers.tick(60001);
    const result = await pending;
    assert.deepEqual(result, { error: 'User denied permission' });
    // Late response for the same id must be a harmless no-op (no throw, no
    // second resolution). pendingApprovals no longer holds the id.
    assert.doesNotThrow(() => respond(id, true));
  });
});

describe('trusted-origin auto-path (general signer)', () => {
  let keypair;

  beforeEach(async () => {
    for (const k of Object.keys(stores.local)) delete stores.local[k];
    for (const k of Object.keys(stores.session)) delete stores.session[k];
    windowsCreated.length = 0;
    keypair = await generateKeypair();
    await storeKeypair(keypair.privateKey, keypair.publicKey);
  });

  it('signs a kind-27235 Solid event with NO prompt when the origin is trusted', async () => {
    await addTrustedOrigin('https://pod.test');
    const result = await send({ type: 'SIGN_EVENT', event: SOLID_EVENT, origin: 'https://pod.test' });
    assert.equal(windowsCreated.length, 0, 'trusted origin must not open a popup');
    assert.equal(result.kind, 27235);
    assert.equal(result.pubkey, keypair.publicKey);
    assert.equal(result.sig.length, 128);
  });

  it('signs a non-Solid kind with NO prompt when the origin is trusted (general signer)', async () => {
    // The forum publishes kind 0/10002/22242 on every load; a trusted origin
    // must sign these without a per-event prompt or Podkey is unusable as a
    // general NIP-07 signer. autoSign is irrelevant — trust is the grant.
    await addTrustedOrigin('https://pod.test');
    const result = await send({ type: 'SIGN_EVENT', event: NOTE_EVENT, origin: 'https://pod.test' });
    assert.equal(windowsCreated.length, 0, 'trusted origin signs any kind without a popup');
    assert.equal(result.kind, 1);
    assert.equal(result.sig.length, 128);
  });

  it('ALWAYS prompts an untrusted origin, regardless of autoSign', async () => {
    // No silent first-use: an origin the user has never approved must prompt,
    // even for a Solid event and even with the autoSign convenience enabled.
    await setAutoSign(true);
    const pending = send({ type: 'SIGN_EVENT', event: SOLID_EVENT, origin: 'https://untrusted.test' });
    await flush();
    assert.equal(windowsCreated.length, 1, 'untrusted origin must require explicit approval');
    respond(lastRequestId(), true);
    const result = await pending;
    assert.equal(result.kind, 27235);
  });

  it('approving an untrusted signing request trusts the origin (no re-prompt, any kind)', async () => {
    // First request: untrusted -> prompt -> approve (establishes trust).
    const first = send({ type: 'SIGN_EVENT', event: SOLID_EVENT, origin: 'https://new.test' });
    await flush();
    assert.equal(windowsCreated.length, 1);
    respond(lastRequestId(), true);
    await first;
    // Second request from the now-trusted origin — a *different* (non-Solid)
    // kind — auto-signs with no further popup.
    const second = await send({ type: 'SIGN_EVENT', event: NOTE_EVENT, origin: 'https://new.test' });
    assert.equal(windowsCreated.length, 1, 'origin became trusted; no second popup');
    assert.equal(second.kind, 1);
  });
});
