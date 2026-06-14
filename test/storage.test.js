/**
 * Tests for Podkey storage functions
 * Note: These tests require Chrome extension APIs, so they may need mocking
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';

// Mock chrome.storage for testing. The extension uses two areas: session
// (in-memory private key) and local (persisted public key + settings), so the
// mock backs each area with its own store.
function makeArea (store) {
  return {
    get: async (keys) => {
      const result = {};
      if (Array.isArray(keys)) {
        keys.forEach(key => {
          result[key] = store[key];
        });
      } else if (keys) {
        Object.keys(keys).forEach(key => {
          result[key] = store[key] || keys[key];
        });
      } else {
        return { ...store };
      }
      return result;
    },
    set: async (items) => {
      Object.assign(store, items);
    },
    remove: async (keys) => {
      if (Array.isArray(keys)) {
        keys.forEach(key => delete store[key]);
      } else {
        delete store[keys];
      }
    }
  };
}

const mockStorage = {
  localData: {},
  sessionData: {}
};
mockStorage.local = makeArea(mockStorage.localData);
mockStorage.session = makeArea(mockStorage.sessionData);

// Set up global chrome mock
global.chrome = { storage: mockStorage };

// Import after setting up mock
const {
  storeKeypair,
  getKeypair,
  hasKeypair,
  deleteKeypair,
  addTrustedOrigin,
  isTrustedOrigin,
  getAutoSign,
  setAutoSign
} = await import('../src/storage.js');

describe('Storage Functions', () => {
  // Clear storage before each test
  const clearStorage = () => {
    mockStorage.localData = {};
    mockStorage.sessionData = {};
    mockStorage.local = makeArea(mockStorage.localData);
    mockStorage.session = makeArea(mockStorage.sessionData);
  };

  describe('storeKeypair / getKeypair', () => {
    it('should store and retrieve a keypair', async () => {
      clearStorage();
      const privateKey = 'a'.repeat(64);
      const publicKey = 'b'.repeat(64);

      await storeKeypair(privateKey, publicKey);
      const retrieved = await getKeypair();

      assert(retrieved, 'Keypair should be retrieved');
      assert.strictEqual(retrieved.privateKey, privateKey);
      assert.strictEqual(retrieved.publicKey, publicKey);
    });

    it('should return null if keypair does not exist', async () => {
      clearStorage();
      const retrieved = await getKeypair();
      assert.strictEqual(retrieved, null);
    });
  });

  describe('hasKeypair', () => {
    it('should return false when no keypair exists', async () => {
      clearStorage();
      assert.strictEqual(await hasKeypair(), false);
    });

    it('should return true when keypair exists', async () => {
      clearStorage();
      await storeKeypair('a'.repeat(64), 'b'.repeat(64));
      assert.strictEqual(await hasKeypair(), true);
    });
  });

  describe('deleteKeypair', () => {
    it('should delete stored keypair', async () => {
      clearStorage();
      await storeKeypair('a'.repeat(64), 'b'.repeat(64));
      assert.strictEqual(await hasKeypair(), true);

      await deleteKeypair();
      assert.strictEqual(await hasKeypair(), false);
    });
  });

  describe('trusted origins', () => {
    it('should add and check trusted origin', async () => {
      clearStorage();
      const origin = 'https://example.com';

      assert.strictEqual(await isTrustedOrigin(origin), false);
      await addTrustedOrigin(origin);
      assert.strictEqual(await isTrustedOrigin(origin), true);
    });
  });

  describe('auto-sign', () => {
    it('should get default auto-sign value', async () => {
      clearStorage();
      const autoSign = await getAutoSign();
      assert.strictEqual(typeof autoSign, 'boolean');
    });

    it('should set and get auto-sign value', async () => {
      clearStorage();
      await setAutoSign(false);
      assert.strictEqual(await getAutoSign(), false);

      await setAutoSign(true);
      assert.strictEqual(await getAutoSign(), true);
    });
  });
});
