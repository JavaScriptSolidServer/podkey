/**
 * Podkey - Popup UI Logic
 */
import {
  PASSKEY_CONFIG_KEY,
  createPasskey,
  deriveNostrKey,
  fromBase64Url,
  getPasskeyPrf,
  newPasskeySalt,
  toBase64Url,
  unwrapPrivateKey,
  wrapPrivateKey
} from '../src/passkey.js';
import { hexToNsec } from '../src/keyformat.js';

// Set DEBUG=true to log identity material (public key / DID) for local
// debugging. Off by default so the popup never prints the user's pubkey.
const DEBUG = false;

// UI State
let currentScreen = 'setup';

// A derived identity waiting on the backup acknowledgment. Nothing is
// persisted until the user confirms the backup, so abandoning this screen
// (cancel or closing the window) leaves no partial state anywhere.
let pendingDerivedIdentity = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  console.log('[Podkey Popup] DOMContentLoaded fired');
  await checkKeypairStatus();
  setupEventListeners();
  console.log('[Podkey Popup] Initialization complete');

  // When relaunched as a dedicated passkey window (?flow=…), start the
  // requested ceremony immediately — see runPasskeyFlow.
  const flow = new URLSearchParams(location.search).get('flow');
  if (flow === 'create') handleCreatePasskeyIdentity();
  else if (flow === 'enable') handleEnablePasskeyUnlock();
  else if (flow === 'unlock') handlePasskeyUnlock();
});

/**
 * Run a WebAuthn ceremony in a context that survives losing focus. The
 * toolbar action popup is destroyed on blur — and the platform authenticator
 * UI takes focus — so a ceremony started there can be killed mid-flight.
 * A chrome.windows.create popup (like the background's unlock window) is not,
 * so when invoked from the action popup we relaunch this page into one and
 * let ?flow= restart the ceremony there.
 */
async function runPasskeyFlow(flow, handler) {
  let inOwnWindow = false;
  try {
    inOwnWindow = (await chrome.windows.getCurrent()).type === 'popup';
  } catch { /* fall through: treat as action popup and relaunch */ }
  if (inOwnWindow) {
    await handler();
    return;
  }
  await chrome.windows.create({
    url: chrome.runtime.getURL(`popup/popup.html?flow=${flow}`),
    type: 'popup',
    width: 400,
    height: 560,
    focused: true
  });
  window.close();
}

/**
 * Check if keypair exists and show appropriate screen
 */
async function checkKeypairStatus() {
  console.log('[Podkey Popup] Checking keypair status...');
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_KEYPAIR_STATUS' });
    if (DEBUG) console.log('[Podkey Popup] Keypair status response:', response);

    // Three states: 'unlocked' -> main, 'locked' -> unlock, 'none' -> setup.
    // (`state` falls back to exists for forward/back compatibility.)
    const state = response.state || (response.exists ? 'unlocked' : 'none');
    if (state === 'unlocked') {
      showMainScreen(response);
    } else if (state === 'locked') {
      showUnlockScreen(response);
    } else {
      showSetupScreen();
    }
  } catch (error) {
    console.error('[Podkey Popup] Error checking keypair status:', error);
    showSetupScreen();
  }
}

/**
 * Show setup screen
 */
function showSetupScreen() {
  console.log('[Podkey Popup] Showing setup screen');
  hideAllScreens();
  const setupScreen = document.getElementById('setupScreen');
  console.log('[Podkey Popup] Setup screen element:', setupScreen);
  setupScreen.style.display = 'block';
  currentScreen = 'setup';
  console.log('[Podkey Popup] Setup screen display set to block');
}

async function getPasskeyConfig() {
  const { [PASSKEY_CONFIG_KEY]: config } = await chrome.storage.local.get([PASSKEY_CONFIG_KEY]);
  return config || null;
}

/**
 * Show generate screen (set an encryption passphrase for a new key)
 */
function showGenerateScreen() {
  hideAllScreens();
  document.getElementById('generatePassphrase').value = '';
  document.getElementById('generatePassphraseConfirm').value = '';
  document.getElementById('generateScreen').style.display = 'block';
  currentScreen = 'generate';
  document.getElementById('generatePassphrase').focus();
}

/**
 * Show unlock screen (encrypted vault present but locked)
 */
function showUnlockScreen(status) {
  hideAllScreens();
  const pk = status && status.publicKey;
  document.getElementById('unlockIdentity').textContent = pk
    ? `Unlock ${pk.slice(0, 8)}…${pk.slice(-4)}`
    : 'Enter your passphrase to unlock your key';
  document.getElementById('unlockPassphrase').value = '';
  document.getElementById('unlockScreen').style.display = 'block';
  currentScreen = 'unlock';
  getPasskeyConfig().then(config => {
    const passkeyBtn = document.getElementById('passkeyUnlockBtn');
    const hasPasskey = !!config;
    passkeyBtn.hidden = !hasPasskey;
    document.getElementById('unlockDivider').hidden = !hasPasskey || config.mode === 'derived';
    document.querySelector('label[for="unlockPassphrase"]').hidden = config?.mode === 'derived';
    document.getElementById('unlockPassphrase').hidden = config?.mode === 'derived';
    document.getElementById('unlockBtn').hidden = config?.mode === 'derived';
    if (!hasPasskey) document.getElementById('unlockPassphrase').focus();
  });
}

/**
 * Show import screen
 */
function showImportScreen() {
  hideAllScreens();
  document.getElementById('importScreen').style.display = 'block';
  currentScreen = 'import';
}

/**
 * Show main screen
 */
async function showMainScreen(status) {
  hideAllScreens();
  document.getElementById('mainScreen').style.display = 'block';
  currentScreen = 'main';

  // Display identity
  document.getElementById('publicKey').textContent = status.publicKey;
  document.getElementById('did').textContent = status.did;

  // Load trusted sites
  await loadTrustedSites();

  // Load auto-sign setting (defaults OFF — must match storage.getAutoSign,
  // which keeps silent trusted-origin Solid / NIP-98 signing strictly opt-in).
  const { podkey_auto_sign: autoSign = false } = await chrome.storage.local.get(['podkey_auto_sign']);
  document.getElementById('autoSignToggle').checked = autoSign;

  const config = await getPasskeyConfig();
  const passkeyBtn = document.getElementById('enablePasskeyBtn');
  passkeyBtn.hidden = config?.mode === 'derived';
  passkeyBtn.textContent = config ? 'Replace' : 'Set up';
  document.getElementById('passkeySettingDesc').textContent = config?.mode === 'derived'
    ? 'This identity is derived from your passkey.'
    : config
      ? 'Enabled. Your passphrase remains available for recovery.'
      : 'Use biometrics or a security key instead of typing your passphrase.';
}

/**
 * Hide all screens
 */
function hideAllScreens() {
  document.querySelectorAll('.screen').forEach(screen => {
    screen.style.display = 'none';
  });
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
  console.log('[Podkey Popup] Setting up event listeners');
  // Setup screen
  document.getElementById('generateBtn').addEventListener('click', () => showGenerateScreen());
  document.getElementById('importBtn').addEventListener('click', () => showImportScreen());
  document.getElementById('passkeyDerivedBtn').addEventListener('click', () => runPasskeyFlow('create', handleCreatePasskeyIdentity));

  // Generate screen
  document.getElementById('generateConfirmBtn').addEventListener('click', handleGenerate);
  document.getElementById('generateCancelBtn').addEventListener('click', () => showSetupScreen());

  // Unlock screen
  document.getElementById('unlockBtn').addEventListener('click', handleUnlock);
  document.getElementById('passkeyUnlockBtn').addEventListener('click', () => runPasskeyFlow('unlock', handlePasskeyUnlock));
  document.getElementById('unlockPassphrase').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleUnlock();
  });
  document.getElementById('forgetKeyBtn').addEventListener('click', handleForgetKey);

  // Import screen
  document.getElementById('importConfirmBtn').addEventListener('click', handleImport);
  document.getElementById('importCancelBtn').addEventListener('click', () => showSetupScreen());

  // Main screen
  document.getElementById('copyBtn').addEventListener('click', handleCopy);
  document.getElementById('autoSignToggle').addEventListener('change', handleAutoSignToggle);
  document.getElementById('exportBtn').addEventListener('click', handleExport);
  document.getElementById('lockBtn').addEventListener('click', handleLock);
  // Same wipe-and-return-to-setup action as the unlock screen's link, surfaced
  // on the main screen so an existing user can reset to the init state (and
  // reach the passkey-derived creation flow) without locking first.
  document.getElementById('resetKeyBtn').addEventListener('click', handleForgetKey);
  document.getElementById('enablePasskeyBtn').addEventListener('click', () => runPasskeyFlow('enable', handleEnablePasskeyUnlock));

  // Passkey backup screen
  document.getElementById('backupAckCheck').addEventListener('change', (e) => {
    document.getElementById('backupFinishBtn').disabled = !e.target.checked;
  });
  document.getElementById('backupCopyBtn').addEventListener('click', handleBackupCopy);
  document.getElementById('backupFinishBtn').addEventListener('click', handleBackupFinish);
  document.getElementById('backupCancelBtn').addEventListener('click', () => {
    pendingDerivedIdentity = null;
    showSetupScreen();
  });
}

async function registerPrfPasskey(label) {
  const prfSalt = newPasskeySalt();
  const { credentialId } = await createPasskey(prfSalt, label);
  // Key material comes from a get() assertion — the operation every future
  // unlock performs — so what we derive or wrap now is exactly what the
  // passkey will reproduce later. (Second prompt is the cost of that proof.)
  const prfOutput = await getPasskeyPrf(credentialId, prfSalt);
  return { credentialId, prfOutput, prfSalt };
}

async function handleCreatePasskeyIdentity() {
  const confirmed = confirm(
    'This advanced mode derives your identity from a passkey. If the passkey is lost or unavailable, the identity cannot be recovered without the private-key backup you will be shown next.\n\nContinue?'
  );
  if (!confirmed) return;
  const btn = document.getElementById('passkeyDerivedBtn');
  try {
    btn.disabled = true;
    btn.textContent = 'Creating passkey…';
    const { credentialId, prfOutput, prfSalt } = await registerPrfPasskey('Podkey Nostr identity');
    const derivationSalt = newPasskeySalt();
    const privateKey = await deriveNostrKey(prfOutput, derivationSalt);
    // Persist nothing yet: the identity only comes into existence once the
    // user has acknowledged the backup on the next screen.
    pendingDerivedIdentity = {
      privateKey,
      config: {
        v: 1, mode: 'derived', credentialId,
        prfSalt: toBase64Url(prfSalt), derivationSalt: toBase64Url(derivationSalt)
      }
    };
    showBackupScreen(privateKey);
  } catch (error) {
    alert(error.message || 'Could not create a passkey identity.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create identity from a passkey';
  }
}

/**
 * Show the backup-acknowledgment gate for a freshly derived identity.
 */
function showBackupScreen(privateKey) {
  hideAllScreens();
  document.getElementById('backupNsec').textContent = hexToNsec(privateKey);
  document.getElementById('backupAckCheck').checked = false;
  document.getElementById('backupFinishBtn').disabled = true;
  document.getElementById('passkeyBackupScreen').style.display = 'block';
  currentScreen = 'passkeyBackup';
}

async function handleBackupCopy() {
  if (!pendingDerivedIdentity) return;
  try {
    await navigator.clipboard.writeText(hexToNsec(pendingDerivedIdentity.privateKey));
    const label = document.querySelector('#backupCopyBtn .btn-copy-label');
    const original = label.textContent;
    label.textContent = 'Copied';
    setTimeout(() => { label.textContent = original; }, 2000);
  } catch (error) {
    alert('Failed to copy: ' + error.message);
  }
}

async function handleBackupFinish() {
  if (!pendingDerivedIdentity) return;
  const btn = document.getElementById('backupFinishBtn');
  try {
    btn.disabled = true;
    btn.textContent = 'Creating…';
    // Config before key: if this is interrupted after the config write, the
    // status handler reports a locked passkey identity and the next passkey
    // unlock re-derives and stores the key — whereas key-before-config left
    // an orphaned public key and no way back to this identity.
    await chrome.storage.local.set({ [PASSKEY_CONFIG_KEY]: pendingDerivedIdentity.config });
    const response = await chrome.runtime.sendMessage({
      type: 'SET_SESSION_KEY', privateKey: pendingDerivedIdentity.privateKey
    });
    if (response?.error) {
      await chrome.storage.local.remove([PASSKEY_CONFIG_KEY]);
      throw new Error(response.error);
    }
    pendingDerivedIdentity = null;
    await showMainScreen(response);
  } catch (error) {
    alert(error.message || 'Could not create a passkey identity.');
    btn.disabled = !document.getElementById('backupAckCheck').checked;
  } finally {
    btn.textContent = 'Create identity';
  }
}

async function handleEnablePasskeyUnlock() {
  const btn = document.getElementById('enablePasskeyBtn');
  try {
    btn.disabled = true;
    btn.textContent = 'Waiting…';
    const { podkey_private_key: privateKey } = await chrome.storage.session.get(['podkey_private_key']);
    if (!privateKey) throw new Error('Unlock Podkey before setting up passkey unlock');
    const { credentialId, prfOutput, prfSalt } = await registerPrfPasskey('Podkey unlock');
    const wrapped = await wrapPrivateKey(privateKey, prfOutput);
    await chrome.storage.local.set({ [PASSKEY_CONFIG_KEY]: {
      v: 1, mode: 'wrapped', credentialId, prfSalt: toBase64Url(prfSalt), wrapped
    } });
    await showMainScreen(await chrome.runtime.sendMessage({ type: 'GET_KEYPAIR_STATUS' }));
  } catch (error) {
    alert(error.message || 'Could not enable passkey unlock.');
  } finally {
    btn.disabled = false;
  }
}

async function handlePasskeyUnlock() {
  const btn = document.getElementById('passkeyUnlockBtn');
  try {
    btn.disabled = true;
    btn.textContent = 'Waiting for passkey…';
    const config = await getPasskeyConfig();
    if (!config) throw new Error('No passkey is configured');
    const prfOutput = await getPasskeyPrf(config.credentialId, fromBase64Url(config.prfSalt));
    const privateKey = config.mode === 'derived'
      ? await deriveNostrKey(prfOutput, fromBase64Url(config.derivationSalt))
      : await unwrapPrivateKey(config.wrapped, prfOutput);
    const response = await chrome.runtime.sendMessage({ type: 'SET_SESSION_KEY', privateKey });
    if (response?.error) throw new Error(response.error);
    await showMainScreen(response);
  } catch (error) {
    alert(error.message || 'Passkey unlock failed.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock with passkey';
  }
}

/**
 * Validate a passphrase + confirmation pair. Returns the passphrase or null
 * (after alerting) when invalid.
 */
function readPassphrase(passId, confirmId) {
  const pass = document.getElementById(passId).value;
  const confirm = document.getElementById(confirmId).value;
  if (pass.length < 8) {
    alert('Passphrase must be at least 8 characters.');
    return null;
  }
  if (pass !== confirm) {
    alert('Passphrases do not match.');
    return null;
  }
  return pass;
}

/**
 * Handle generate new keypair (encrypts it under the chosen passphrase)
 */
async function handleGenerate() {
  const passphrase = readPassphrase('generatePassphrase', 'generatePassphraseConfirm');
  if (!passphrase) return;

  const btn = document.getElementById('generateConfirmBtn');
  const original = btn.textContent;
  try {
    btn.textContent = 'Generating…';
    btn.disabled = true;

    const response = await chrome.runtime.sendMessage({ type: 'GENERATE_KEYPAIR', passphrase });

    if (DEBUG) console.log('[Podkey] Keypair generated:', response.publicKey);

    await showMainScreen({
      exists: true,
      publicKey: response.publicKey,
      did: response.did
    });
  } catch (error) {
    alert('Error generating keypair: ' + error.message);
  } finally {
    btn.textContent = original;
    btn.disabled = false;
  }
}

/**
 * Handle unlock: decrypt the vault into the session with the passphrase
 */
async function handleUnlock() {
  const passphrase = document.getElementById('unlockPassphrase').value;
  if (!passphrase) {
    alert('Please enter your passphrase.');
    return;
  }

  const btn = document.getElementById('unlockBtn');
  const original = btn.textContent;
  try {
    btn.textContent = 'Unlocking…';
    btn.disabled = true;

    const response = await chrome.runtime.sendMessage({ type: 'UNLOCK_VAULT', passphrase });

    document.getElementById('unlockPassphrase').value = '';
    await showMainScreen({
      exists: true,
      publicKey: response.publicKey,
      did: response.did
    });
  } catch (error) {
    // 'Incorrect passphrase' from the background — keep it on-screen to retry.
    alert(error.message || 'Unlock failed.');
  } finally {
    btn.textContent = original;
    btn.disabled = false;
  }
}

/**
 * Handle lock: drop the in-memory key (vault stays encrypted on disk)
 */
async function handleLock() {
  await chrome.runtime.sendMessage({ type: 'LOCK_VAULT' });
  const status = await chrome.runtime.sendMessage({ type: 'GET_KEYPAIR_STATUS' });
  showUnlockScreen(status);
}

/**
 * Handle "forget key & start over": wipe the encrypted vault and identity so
 * the user can generate or import a different key. Irreversible.
 */
async function handleForgetKey(event) {
  if (event) event.preventDefault();
  const confirmed = confirm(
    '⚠️ This deletes the encrypted key stored on this device.\n\n' +
    'If you have not backed up your private key, you will lose access to this ' +
    'identity permanently.\n\nContinue?'
  );
  if (!confirmed) return;

  await chrome.storage.session.remove(['podkey_private_key']);
  await chrome.storage.local.remove(['podkey_vault', 'podkey_public_key', PASSKEY_CONFIG_KEY]);
  showSetupScreen();
}

/**
 * Handle import keypair
 */
async function handleImport() {
  try {
    const privateKey = document.getElementById('privateKeyInput').value.trim();

    if (!privateKey) {
      alert('Please enter a private key');
      return;
    }

    const passphrase = readPassphrase('importPassphrase', 'importPassphraseConfirm');
    if (!passphrase) return;

    const btn = document.getElementById('importConfirmBtn');
    btn.textContent = 'Importing...';
    btn.disabled = true;

    const response = await chrome.runtime.sendMessage({
      type: 'IMPORT_KEYPAIR',
      privateKey,
      passphrase
    });

    if (DEBUG) console.log('[Podkey] Keypair imported:', response.publicKey);

    // Clear inputs (private key + passphrases)
    document.getElementById('privateKeyInput').value = '';
    document.getElementById('importPassphrase').value = '';
    document.getElementById('importPassphraseConfirm').value = '';

    // Show main screen
    await showMainScreen({
      exists: true,
      publicKey: response.publicKey,
      did: response.did
    });
  } catch (error) {
    alert('Error importing keypair: ' + error.message);
    document.getElementById('importConfirmBtn').textContent = 'Import';
    document.getElementById('importConfirmBtn').disabled = false;
  }
}

/**
 * Handle copy public key
 */
async function handleCopy() {
  const publicKey = document.getElementById('publicKey').textContent;

  try {
    await navigator.clipboard.writeText(publicKey);

    const btn = document.getElementById('copyBtn');
    const labelEl = btn.querySelector('.btn-copy-label');
    const originalText = labelEl.textContent;
    labelEl.textContent = 'Copied';
    btn.classList.add('copied');

    setTimeout(() => {
      labelEl.textContent = originalText;
      btn.classList.remove('copied');
    }, 2000);
  } catch (error) {
    alert('Failed to copy: ' + error.message);
  }
}

/**
 * Handle auto-sign toggle
 */
async function handleAutoSignToggle(event) {
  const enabled = event.target.checked;

  await chrome.storage.local.set({
    podkey_auto_sign: enabled
  });

  console.log('[Podkey] Auto-sign:', enabled);
}

/**
 * Handle export private key
 */
async function handleExport() {
  const confirmed = confirm(
    '⚠️ WARNING ⚠️\n\n' +
    'You are about to reveal your private key.\n\n' +
    'NEVER share this with anyone!\n' +
    'Anyone with your private key can control your identity.\n\n' +
    'Continue?'
  );

  if (!confirmed) return;

  try {
    // The unlocked private key lives in session storage. If the vault is locked
    // (e.g. after a browser restart) there is nothing to export until unlocked.
    let { podkey_private_key: privateKey } = await chrome.storage.session.get(['podkey_private_key']);
    if (!privateKey) {
      ({ podkey_private_key: privateKey } = await chrome.storage.local.get(['podkey_private_key']));
    }

    if (!privateKey) {
      alert('Podkey is locked. Unlock with your passphrase first, then export.');
      return;
    }

    // Show private key
    prompt('Your Private Key (keep this safe!):', privateKey);
  } catch (error) {
    alert('Error exporting key: ' + error.message);
  }
}

/**
 * Load and display trusted sites
 */
async function loadTrustedSites() {
  const { podkey_trusted_origins: trusted = {} } = await chrome.storage.local.get(['podkey_trusted_origins']);

  const listEl = document.getElementById('trustedList');
  const origins = Object.keys(trusted);

  // Rebuild the list with the DOM API only — no innerHTML on this surface,
  // since origin strings originate from web pages.
  listEl.replaceChildren();

  if (origins.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = 'No trusted sites yet';
    listEl.appendChild(empty);
    return;
  }

  origins.sort().forEach(origin => {
    const div = document.createElement('div');
    div.className = 'trusted-item';

    const span = document.createElement('span');
    span.className = 'trusted-origin';
    span.textContent = origin;

    const btn = document.createElement('button');
    btn.className = 'btn-remove';
    btn.dataset.origin = origin;
    btn.textContent = 'Remove';

    btn.addEventListener('click', async () => {
      await removeTrustedSite(origin);
      await loadTrustedSites(); // Reload
    });

    div.appendChild(span);
    div.appendChild(btn);
    listEl.appendChild(div);
  });
}

/**
 * Remove a trusted site
 */
async function removeTrustedSite(origin) {
  const { podkey_trusted_origins: trusted = {} } = await chrome.storage.local.get(['podkey_trusted_origins']);

  delete trusted[origin];

  await chrome.storage.local.set({
    podkey_trusted_origins: trusted
  });

  console.log('[Podkey] Removed trusted site:', origin);
}

// Listen for storage changes (local for trusted sites / pubkey, session for private key)
chrome.storage.onChanged.addListener((changes, areaName) => {
  if ((areaName === 'local' || areaName === 'session') && currentScreen === 'main') {
    loadTrustedSites();
  }
});
