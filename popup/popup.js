/**
 * Podkey - Popup UI Logic
 */

// UI State
let currentScreen = 'setup';

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  console.log('[Podkey Popup] DOMContentLoaded fired');
  await checkKeypairStatus();
  setupEventListeners();
  console.log('[Podkey Popup] Initialization complete');
});

/**
 * Check if keypair exists and show appropriate screen
 */
async function checkKeypairStatus() {
  console.log('[Podkey Popup] Checking keypair status...');
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_KEYPAIR_STATUS' });
    console.log('[Podkey Popup] Keypair status response:', response);

    if (response.exists) {
      console.log('[Podkey Popup] Keypair exists, showing main screen');
      showMainScreen(response);
    } else {
      console.log('[Podkey Popup] No keypair, showing setup screen');
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

  // Load auto-sign setting
  const { podkey_auto_sign: autoSign = true } = await chrome.storage.local.get(['podkey_auto_sign']);
  document.getElementById('autoSignToggle').checked = autoSign;
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
  document.getElementById('generateBtn').addEventListener('click', handleGenerate);
  document.getElementById('importBtn').addEventListener('click', () => showImportScreen());

  // Import screen
  document.getElementById('importConfirmBtn').addEventListener('click', handleImport);
  document.getElementById('importCancelBtn').addEventListener('click', () => showSetupScreen());

  // Main screen
  document.getElementById('copyBtn').addEventListener('click', handleCopy);
  document.getElementById('autoSignToggle').addEventListener('change', handleAutoSignToggle);
  document.getElementById('exportBtn').addEventListener('click', handleExport);
}

/**
 * Handle generate new keypair
 */
async function handleGenerate() {
  try {
    const btn = document.getElementById('generateBtn');
    btn.textContent = 'Generating...';
    btn.disabled = true;

    const response = await chrome.runtime.sendMessage({ type: 'GENERATE_KEYPAIR' });

    console.log('[Podkey] Keypair generated:', response.publicKey);

    // Show main screen
    await showMainScreen({
      exists: true,
      publicKey: response.publicKey,
      did: response.did
    });
  } catch (error) {
    alert('Error generating keypair: ' + error.message);
    document.getElementById('generateBtn').textContent = '✨ Generate New Key';
    document.getElementById('generateBtn').disabled = false;
  }
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

    const btn = document.getElementById('importConfirmBtn');
    btn.textContent = 'Importing...';
    btn.disabled = true;

    const response = await chrome.runtime.sendMessage({
      type: 'IMPORT_KEYPAIR',
      privateKey
    });

    console.log('[Podkey] Keypair imported:', response.publicKey);

    // Clear input
    document.getElementById('privateKeyInput').value = '';

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
    const originalText = btn.textContent;
    btn.textContent = '✅ Copied!';

    setTimeout(() => {
      btn.textContent = originalText;
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
    const { podkey_private_key: privateKey } = await chrome.storage.local.get(['podkey_private_key']);

    if (!privateKey) {
      alert('No private key found');
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

  if (origins.length === 0) {
    listEl.innerHTML = '<div class="empty-state">No trusted sites yet</div>';
    return;
  }

  listEl.innerHTML = '';
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

// Listen for storage changes
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && currentScreen === 'main') {
    loadTrustedSites();
  }
});
