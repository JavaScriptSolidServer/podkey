/**
 * Podkey - NIP-07 window.nostr Provider
 * Injected into all web pages to provide Nostr signing capabilities
 */

(function() {
  'use strict';

  // Only inject once
  if (window.nostr) {
    console.log('[Podkey] window.nostr already exists, skipping injection');
    return;
  }

  /**
   * NIP-07 window.nostr API implementation
   */
  window.nostr = {
    /**
     * Get the user's public key
     * @returns {Promise<string>} 64-char hex public key
     */
    async getPublicKey() {
      return sendMessageToExtension({ type: 'GET_PUBLIC_KEY' });
    },

    /**
     * Sign an event
     * @param {object} event - Unsigned event
     * @returns {Promise<object>} Signed event with id, pubkey, sig
     */
    async signEvent(event) {
      // Validate event structure
      if (!event || typeof event !== 'object') {
        throw new Error('Event must be an object');
      }

      if (typeof event.kind !== 'number') {
        throw new Error('Event kind must be a number');
      }

      if (typeof event.created_at !== 'number') {
        throw new Error('Event created_at must be a number');
      }

      if (!Array.isArray(event.tags)) {
        throw new Error('Event tags must be an array');
      }

      if (typeof event.content !== 'string') {
        throw new Error('Event content must be a string');
      }

      return sendMessageToExtension({
        type: 'SIGN_EVENT',
        event
      });
    },

    /**
     * Get relays (optional NIP-07 extension)
     * @returns {Promise<object>} Relay configuration
     */
    async getRelays() {
      return sendMessageToExtension({ type: 'GET_RELAYS' });
    },

    /**
     * Encrypt (NIP-04)
     * @param {string} pubkey - Recipient public key
     * @param {string} plaintext - Message to encrypt
     * @returns {Promise<string>} Encrypted message
     */
    async nip04 = {
      encrypt: async (pubkey, plaintext) => {
        return sendMessageToExtension({
          type: 'NIP04_ENCRYPT',
          pubkey,
          plaintext
        });
      },

      decrypt: async (pubkey, ciphertext) => {
        return sendMessageToExtension({
          type: 'NIP04_DECRYPT',
          pubkey,
          ciphertext
        });
      }
    }
  };

  /**
   * Send message to extension background script
   * @param {object} message - Message to send
   * @returns {Promise<any>} Response from extension
   */
  async function sendMessageToExtension(message) {
    return new Promise((resolve, reject) => {
      // Create custom event to communicate with content script
      const eventId = Math.random().toString(36).substring(7);

      const handler = (event) => {
        if (event.detail.id === eventId) {
          window.removeEventListener('podkey-response', handler);

          if (event.detail.error) {
            reject(new Error(event.detail.error));
          } else {
            resolve(event.detail.result);
          }
        }
      };

      window.addEventListener('podkey-response', handler);

      // Send request
      window.dispatchEvent(new CustomEvent('podkey-request', {
        detail: {
          id: eventId,
          ...message
        }
      }));

      // Timeout after 30 seconds
      setTimeout(() => {
        window.removeEventListener('podkey-response', handler);
        reject(new Error('Podkey request timeout'));
      }, 30000);
    });
  }

  console.log('[Podkey] window.nostr provider injected ✨');

  // Announce that nostr is ready
  window.dispatchEvent(new Event('nostr-ready'));
})();
