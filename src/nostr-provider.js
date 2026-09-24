/**
 * Podkey - NIP-07 window.nostr Provider
 * Injected into all web pages to provide Nostr signing capabilities
 */

(function () {
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
    async getPublicKey () {
      return sendMessageToExtension({ type: 'GET_PUBLIC_KEY' });
    },

    /**
     * Sign an event
     * @param {object} event - Unsigned event
     * @returns {Promise<object>} Signed event with id, pubkey, sig
     */
    async signEvent (event) {
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

    // NIP-04 is intentionally not provided: it is a deprecated, unauthenticated
    // scheme and Podkey only ships NIP-44 (v2). Advertising window.nostr.nip04
    // would make feature-detection lie. NIP-07 getRelays is also omitted because
    // Podkey holds no relay list — a missing method is the honest signal.

    /**
     * Encrypt / decrypt (NIP-44 v2)
     * Used by NIP-17 / NIP-59 (gift-wrapped) direct messages. The private key
     * never leaves the background service worker — encryption is performed
     * there and only the resulting payload/plaintext crosses to the page.
     */
    nip44: {
      /**
       * @param {string} pubkey - 64-char hex peer public key
       * @param {string} plaintext - message to encrypt
       * @returns {Promise<string>} base64 NIP-44 v2 payload
       */
      encrypt: async (pubkey, plaintext) => {
        return sendMessageToExtension({
          type: 'NIP44_ENCRYPT',
          pubkey,
          plaintext
        });
      },

      /**
       * @param {string} pubkey - 64-char hex peer public key
       * @param {string} ciphertext - base64 NIP-44 v2 payload
       * @returns {Promise<string>} decrypted plaintext
       */
      decrypt: async (pubkey, ciphertext) => {
        return sendMessageToExtension({
          type: 'NIP44_DECRYPT',
          pubkey,
          ciphertext
        });
      }
    },

    /**
     * sidestr spends (sidestr/spec proposals/browser-signer.md). Podkey reads
     * and validates the chain itself, shows the spend in its own window and
     * asks every time; the page supplies only the chain id and the
     * transaction. Rejections carry `code`: rejected, unsupported, not-yours,
     * invalid or unavailable.
     */
    sidestr: Object.freeze({
      version: 1,
      // what a page calls this signer in its own copy ("Podkey will show you this spend")
      name: 'Podkey',

      /**
       * @param {{chain: string, tx: string}} request - chain id and the
       *   transaction as hex (any witness is ignored and replaced)
       * @returns {Promise<{tx: string, txid: string}>} the signed transaction
       */
      signTransaction: async (request) => {
        if (!request || typeof request !== 'object') {
          throw Object.assign(new Error('signTransaction takes { chain, tx }'), { code: 'invalid' });
        }
        return sendMessageToExtension({
          type: 'SIDESTR_SIGN_TRANSACTION',
          chain: request.chain,
          tx: request.tx
        }, SPEND_TIMEOUT_MS);
      }
    })
  };

  // A spend waits for Podkey to read the chain and for the person to decide,
  // so it gets longer than the 30 seconds other requests do. Podkey's own
  // window closes itself before this.
  const SPEND_TIMEOUT_MS = 5 * 60 * 1000;

  /**
   * Send message to extension background script
   * @param {object} message - Message to send
   * @returns {Promise<any>} Response from extension
   */
  async function sendMessageToExtension (message, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
      // Create custom event to communicate with content script
      const eventId = Math.random().toString(36).substring(7);

      let timer = null;
      const handler = (event) => {
        if (event.detail.id === eventId) {
          window.removeEventListener('podkey-response', handler);
          clearTimeout(timer);

          if (event.detail.error) {
            const error = new Error(event.detail.error);
            if (event.detail.code) error.code = event.detail.code;
            reject(error);
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

      // Cleared when the answer arrives, so a spend's five-minute wait does
      // not outlive it.
      timer = setTimeout(() => {
        window.removeEventListener('podkey-response', handler);
        reject(Object.assign(new Error('Podkey request timeout'), { code: 'unavailable' }));
      }, timeoutMs);
    });
  }

  console.log('[Podkey] window.nostr provider injected ✨');

  // Announce that nostr is ready
  window.dispatchEvent(new Event('nostr-ready'));
})();
