/**
 * Tests for NIP-98 auth-header minting in the background service worker:
 *   - token freshness: per-token random nonce -> distinct event id even for the
 *     same (url, method) within the same second (no replayable duplicate)
 *   - exact-origin Solid auto-trust matching (the fix for substring trust)
 *   - body-hash `payload` tag inclusion for losslessly-crossing body types
 *
 * createNip98AuthHeader is module-private, so it is exercised the way the
 * content script reaches it: via the CREATE_NIP98_AUTH_HEADER message. The
 * returned `Nostr <base64>` header is decoded back into the signed event.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

function makeArea (store) {
  return {
    get: async (keys) => {
      const result = {};
      if (Array.isArray(keys)) keys.forEach((k) => { result[k] = store[k]; });
      else if (keys) Object.keys(keys).forEach((k) => { result[k] = store[k] ?? keys[k]; });
      else return { ...store };
      return result;
    },
    set: async (items) => { Object.assign(store, items); },
    remove: async (keys) => { (Array.isArray(keys) ? keys : [keys]).forEach((k) => delete store[k]); }
  };
}

const stores = { local: {}, session: {} };
const captured = { onMessage: null };

global.chrome = {
  runtime: {
    onInstalled: { addListener: () => {} },
    onMessage: { addListener: (fn) => { captured.onMessage = fn; } },
    lastError: null
  },
  windows: { create: () => Promise.resolve({ id: 1 }) },
  storage: { local: makeArea(stores.local), session: makeArea(stores.session) }
};

await import('../src/background.js');
const { generateKeypair } = await import('../src/crypto.js');
const { storeKeypair, setAutoSign, addTrustedOrigin, isTrustedOrigin } = await import('../src/storage.js');

const onMessage = captured.onMessage;
const send = (message) => new Promise((resolve) => { onMessage(message, {}, resolve); });

/** Decode a `Nostr <base64>` header back into the signed event object. */
function decodeHeader (header) {
  assert.equal(typeof header, 'string', 'expected a header string');
  assert.match(header, /^Nostr /, 'NIP-98 header must use the "Nostr " scheme');
  return JSON.parse(Buffer.from(header.slice('Nostr '.length), 'base64').toString('utf8'));
}

const tagValue = (event, name) => {
  const t = event.tags.find((tag) => tag[0] === name);
  return t ? t[1] : undefined;
};

let keypair;
beforeEach(async () => {
  for (const k of Object.keys(stores.local)) delete stores.local[k];
  for (const k of Object.keys(stores.session)) delete stores.session[k];
  keypair = await generateKeypair();
  await storeKeypair(keypair.privateKey, keypair.publicKey);
  await setAutoSign(true);
});

describe('NIP-98 token freshness (per-token nonce)', () => {
  it('mints a kind-27235 event with u, method and a 16-byte nonce tag', async () => {
    await addTrustedOrigin('https://pod.test');
    const event = decodeHeader(await send({
      type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://pod.test/resource', method: 'PUT'
    }));
    assert.equal(event.kind, 27235);
    assert.equal(event.content, '');
    assert.equal(tagValue(event, 'u'), 'https://pod.test/resource');
    assert.equal(tagValue(event, 'method'), 'PUT');
    const nonce = tagValue(event, 'nonce');
    assert.ok(nonce, 'a nonce tag is required for freshness');
    assert.match(nonce, /^[0-9a-f]{32}$/, 'nonce must be 16 random bytes (32 hex chars)');
  });

  it('two tokens for the same (url, method) have distinct ids and nonces', async () => {
    await addTrustedOrigin('https://pod.test');
    const a = decodeHeader(await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://pod.test/x', method: 'GET' }));
    const b = decodeHeader(await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://pod.test/x', method: 'GET' }));

    // created_at has 1s resolution; back-to-back calls usually share it. The
    // nonce is what must differ so the event id (and thus the token) cannot be
    // replayed.
    assert.notEqual(tagValue(a, 'nonce'), tagValue(b, 'nonce'), 'nonces must differ');
    assert.notEqual(a.id, b.id, 'event ids must differ -> no replayable duplicate');
    assert.notEqual(a.sig, b.sig, 'signatures must differ');
  });

  it('each minted event is self-consistent (id binds u/method/nonce)', async () => {
    await addTrustedOrigin('https://pod.test');
    const { verifySignature, getEventHash } = await import('../src/crypto.js');
    const event = decodeHeader(await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://pod.test/y', method: 'POST' }));
    assert.equal(event.id, getEventHash(event), 'id must be the NIP-01 hash of the event');
    assert.equal(await verifySignature(event), true, 'signature must verify against the pubkey');
    assert.equal(event.pubkey, keypair.publicKey);
  });
});

describe('NIP-98 payload body-hash tag', () => {
  it('adds a payload tag with the sha-256 of a string body', async () => {
    await addTrustedOrigin('https://pod.test');
    const body = '{"hello":"world"}';
    const event = decodeHeader(await send({
      type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://pod.test/r', method: 'POST', body
    }));
    const expected = createHash('sha256').update(body, 'utf8').digest('hex');
    assert.equal(tagValue(event, 'payload'), expected);
  });

  it('prefers a page-computed bodyHash over re-hashing the body', async () => {
    await addTrustedOrigin('https://pod.test');
    // The page context (nip98-interceptor) sends only the hash; background must
    // use it verbatim and not require the raw body.
    const bodyHash = createHash('sha256').update('precomputed', 'utf8').digest('hex');
    const event = decodeHeader(await send({
      type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://pod.test/r', method: 'POST', bodyHash
    }));
    assert.equal(tagValue(event, 'payload'), bodyHash);
  });

  it('omits the payload tag when there is no body', async () => {
    await addTrustedOrigin('https://pod.test');
    const event = decodeHeader(await send({
      type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://pod.test/r', method: 'GET'
    }));
    assert.equal(tagValue(event, 'payload'), undefined);
  });
});

describe('Solid auto-trust: exact-origin matching (substring-trust fix)', () => {
  it('auto-trusts an exact trusted Solid host and mints a header', async () => {
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://inrupt.net/profile/card', method: 'GET' });
    assert.equal(typeof header, 'string', 'inrupt.net should be auto-trusted');
    assert.equal(decodeHeader(header).kind, 27235);
    assert.equal(await isTrustedOrigin('https://inrupt.net'), true, 'origin should be persisted as trusted');
  });

  it('does NOT trust a lookalike suffix host (inrupt.net.evil.com)', async () => {
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://inrupt.net.evil.com/steal', method: 'GET' });
    assert.equal(header, null, 'a substring-only match must not be auto-trusted');
    assert.equal(await isTrustedOrigin('https://inrupt.net.evil.com'), false);
  });

  it('does NOT trust an attacker prefix host (evil-inrupt.net)', async () => {
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://evilinrupt.net/x', method: 'GET' });
    assert.equal(header, null);
  });

  it('trusts a legitimate subdomain of a trusted Solid host', async () => {
    // isLikelySolidServer accepts host === trusted || host.endsWith('.'+trusted)
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://alice.solidcommunity.net/profile', method: 'GET' });
    assert.equal(typeof header, 'string', 'a real subdomain should auto-trust');
    assert.equal(decodeHeader(header).kind, 27235);
  });

  it('does NOT auto-trust a non-Solid origin', async () => {
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://example.com/api', method: 'GET' });
    assert.equal(header, null, 'unknown origins require an explicit prompt, not silent NIP-98');
    assert.equal(await isTrustedOrigin('https://example.com'), false);
  });

  it('host matching is case-insensitive on the registrable host (URL-normalized)', async () => {
    // The URL parser lowercases the host, so INRUPT.NET resolves to inrupt.net.
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://INRUPT.NET/x', method: 'GET' });
    assert.equal(typeof header, 'string');
  });

  it('binds the u tag to the exact requested URL', async () => {
    const event = decodeHeader(await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://inrupt.net/a/b?q=1', method: 'GET' }));
    assert.equal(tagValue(event, 'u'), 'https://inrupt.net/a/b?q=1');
  });
});

describe('NIP-98 auto-trust gating', () => {
  it('returns null for a trusted origin when autoSign is OFF', async () => {
    await addTrustedOrigin('https://pod.test');
    await setAutoSign(false);
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://pod.test/r', method: 'GET' });
    assert.equal(header, null, 'autoSign off must suppress silent NIP-98');
  });

  it('does NOT auto-trust a Solid host when autoSign is OFF', async () => {
    await setAutoSign(false);
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://inrupt.net/r', method: 'GET' });
    assert.equal(header, null);
    assert.equal(await isTrustedOrigin('https://inrupt.net'), false, 'no auto-trust without autoSign');
  });

  it('returns null when no keypair exists', async () => {
    for (const k of Object.keys(stores.session)) delete stores.session[k];
    for (const k of Object.keys(stores.local)) delete stores.local[k];
    const header = await send({ type: 'CREATE_NIP98_AUTH_HEADER', url: 'https://inrupt.net/r', method: 'GET' });
    assert.equal(header, null, 'no key -> no header (never throws to the page)');
  });
});
