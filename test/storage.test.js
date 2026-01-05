/**
 * Tests for Podkey storage functions
 * Note: These tests require Chrome extension APIs, so they may need mocking
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';

// Mock chrome.storage for testing
const mockStorage = {
  data: {},
  local: {
    get: async (keys) => {
      const result = {};
      if (Array.isArray(keys)) {
        keys.forEach(key => {
          result[key] = mockStorage.data[key];
        });
      } else if (keys) {
        Object.keys(keys).forEach(key => {
          result[key] = mockStorage.data[key] || keys[key];
        });
      } else {
        return { ...mockStorage.data };
      }
      return result;
    },
    set: async (items) => {
      Object.assign(mockStorage.data, items);
    },
    remove: async (keys) => {
      if (Array.isArray(keys)) {
        keys.forEach(key => delete mockStorage.data[key]);
      } else {
        delete mockStorage.data[keys];
      }
    }
  }
};

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
    mockStorage.data = {};
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
