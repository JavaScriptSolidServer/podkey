/**
 * Tests for the SET_SESSION_KEY background contract (passkey unlock/creation)
 * and the surrounding state-consistency guarantees:
 *
 *   - extension-UI-only guard: privileged message types are rejected when the
 *     message arrives via a content script (sender.tab set) — defence-in-depth
 *     behind the injected.js whitelist
 *   - first use: a valid key is stored and reported as unlocked with the
 *     matching pubkey / did
 *   - identity guard: a key that derives a different pubkey than the stored
 *     identity is rejected ("different identity")
 *   - orphan cleanup: a stored public key with no vault, passkey config, or
 *     session key is removed when status is checked
 *
 * background.js exports nothing and wires its listener onto chrome.runtime at
 * import time, so these tests mock `chrome`, import the module, and drive the
 * captured onMessage listener directly (same harness as consent-approval).
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

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
const captured = { onMessage: null };

const EXT_ID = 'podkeytestextensionid';
global.chrome = {
  runtime: {
    id: EXT_ID,
    onInstalled: { addListener: () => {} },
    onMessage: { addListener: (fn) => { captured.onMessage = fn; } },
    lastError: null
  },
  windows: {
    create: () => Promise.resolve({ id: 1 })
  },
  storage: {
    local: makeArea(stores.local),
    session: makeArea(stores.session)
  }
};

await import('../src/background.js');
const { generateKeypair, getPublicKey } = await import('../src/crypto.js');

const onMessage = captured.onMessage;

// Default sender = one of our own extension pages (the action popup or the
// dedicated ceremony window opened via chrome.windows.create — both report a
// chrome-extension URL for our own id).
const EXT_UI_SENDER = { id: EXT_ID, url: `chrome-extension://${EXT_ID}/popup/popup.html` };

/** Send a message to the background and resolve with sendResponse's value. */
function send (message, sender = EXT_UI_SENDER) {
  return new Promise((resolve) => { onMessage(message, sender, resolve); });
}

describe('SET_SESSION_KEY contract', () => {
  beforeEach(() => {
    for (const k of Object.keys(stores.local)) delete stores.local[k];
    for (const k of Object.keys(stores.session)) delete stores.session[k];
  });

  it('rejects privileged types from a content script (own id, but a web-page URL)', async () => {
    const { privateKey } = await generateKeypair();
    // A content script runs with our extension id in sender.id, but sender.url
    // is the host page — this must NOT be accepted.
    const contentScript = { id: EXT_ID, url: 'https://evil.example/app', tab: { id: 1 } };
    for (const type of ['SET_SESSION_KEY', 'UNLOCK_VAULT', 'GENERATE_KEYPAIR', 'IMPORT_KEYPAIR', 'LOCK_VAULT', 'GET_KEYPAIR_STATUS']) {
      const response = await send({ type, privateKey, passphrase: 'irrelevant' }, contentScript);
      assert.match(response.error, /not allowed from web content/, type);
    }
    assert.equal(stores.session.podkey_private_key, undefined);
    assert.equal(stores.local.podkey_public_key, undefined);
  });

  it('accepts privileged types from the ceremony window (a real tab, own extension URL)', async () => {
    const { privateKey, publicKey } = await generateKeypair();
    // chrome.windows.create popups have a sender.tab AND our extension URL — the
    // guard must allow these, or every passkey unlock breaks.
    const ceremonyWindow = { id: EXT_ID, url: `chrome-extension://${EXT_ID}/popup/popup.html?flow=create`, tab: { id: 9 } };
    const response = await send({ type: 'SET_SESSION_KEY', privateKey }, ceremonyWindow);
    assert.equal(response.state, 'unlocked');
    assert.equal(response.publicKey, publicKey);
  });

  it('stores a first-use key and reports it unlocked', async () => {
    const { privateKey, publicKey } = await generateKeypair();
    const response = await send({ type: 'SET_SESSION_KEY', privateKey });
    assert.equal(response.state, 'unlocked');
    assert.equal(response.publicKey, publicKey);
    assert.equal(response.did, `did:nostr:${publicKey}`);
    assert.equal(stores.session.podkey_private_key, privateKey);
    assert.equal(stores.local.podkey_public_key, publicKey);
  });

  it('accepts the same identity again (re-unlock) without error', async () => {
    const { privateKey } = await generateKeypair();
    await send({ type: 'SET_SESSION_KEY', privateKey });
    delete stores.session.podkey_private_key; // simulate lock / browser restart
    const response = await send({ type: 'SET_SESSION_KEY', privateKey });
    assert.equal(response.state, 'unlocked');
    assert.equal(response.publicKey, getPublicKey(privateKey));
  });

  it('rejects a key that derives a different identity than the stored one', async () => {
    const existing = await generateKeypair();
    stores.local.podkey_public_key = existing.publicKey;
    const other = await generateKeypair();
    const response = await send({ type: 'SET_SESSION_KEY', privateKey: other.privateKey });
    assert.match(response.error, /different identity/);
    assert.equal(stores.session.podkey_private_key, undefined);
  });

  it('rejects malformed key material', async () => {
    const response = await send({ type: 'SET_SESSION_KEY', privateKey: 'not-a-key' });
    assert.ok(response.error);
    assert.equal(stores.session.podkey_private_key, undefined);
  });

  it('GET_KEYPAIR_STATUS clears an orphaned public key (no vault, passkey, or session)', async () => {
    stores.local.podkey_public_key = 'a'.repeat(64);
    const response = await send({ type: 'GET_KEYPAIR_STATUS' });
    assert.equal(response.state, 'none');
    assert.equal(stores.local.podkey_public_key, undefined);
  });

  it('GET_KEYPAIR_STATUS keeps the public key for a locked passkey identity', async () => {
    stores.local.podkey_public_key = 'b'.repeat(64);
    stores.local.podkey_passkey = { v: 1, mode: 'derived', credentialId: 'x', prfSalt: 'y', derivationSalt: 'z' };
    const response = await send({ type: 'GET_KEYPAIR_STATUS' });
    assert.equal(response.state, 'locked');
    assert.equal(response.publicKey, 'b'.repeat(64));
    assert.equal(stores.local.podkey_public_key, 'b'.repeat(64));
  });
});
