/**
 * Podkey — Test / install page logic.
 *
 * Runs in a normal web page (window.nostr is provided by the extension's
 * injected provider). All DOM updates use textContent / createElement — never
 * innerHTML with interpolated values — since signed-event fields and error
 * messages may contain arbitrary strings.
 */

let logCount = 0;

const els = {};
function $(id) {
  return (els[id] ||= document.getElementById(id));
}

/* ---------- Logging ---------- */

function log(message, type = 'info') {
  const logEl = $('eventLog');
  const time = new Date().toLocaleTimeString();

  const entry = document.createElement('div');
  entry.className = 'log-entry';

  const timeSpan = document.createElement('span');
  timeSpan.className = 'log-time';
  timeSpan.textContent = `[${time}]`;

  const messageSpan = document.createElement('span');
  messageSpan.className = `log-${type}`;
  messageSpan.textContent = message;

  entry.appendChild(timeSpan);
  entry.appendChild(messageSpan);
  logEl.insertBefore(entry, logEl.firstChild);

  logCount++;
  while (logEl.children.length > 100) {
    logEl.removeChild(logEl.lastChild);
  }
}

function clearLog() {
  $('eventLog').replaceChildren();
  logCount = 0;
  log('Log cleared', 'info');
}

/* ---------- Result rendering helpers (DOM-only, no innerHTML) ---------- */

/**
 * Render labelled key/value lines into a value-display element.
 * fields: array of [label, value] pairs.
 */
function showResult(id, fields) {
  const el = $(id);
  el.classList.remove('is-error');
  el.replaceChildren();
  el.style.display = 'block';

  for (const [label, value] of fields) {
    const labelEl = document.createElement('span');
    labelEl.className = 'vd-label';
    labelEl.textContent = label;
    el.appendChild(labelEl);

    const valueEl = document.createElement('span');
    valueEl.textContent = value;
    el.appendChild(valueEl);
  }
}

function showPreformatted(id, label, text) {
  const el = $(id);
  el.classList.remove('is-error');
  el.replaceChildren();
  el.style.display = 'block';

  const labelEl = document.createElement('span');
  labelEl.className = 'vd-label';
  labelEl.textContent = label;
  el.appendChild(labelEl);

  const pre = document.createElement('pre');
  pre.textContent = text;
  el.appendChild(pre);
}

function showError(id, message) {
  const el = $(id);
  el.classList.add('is-error');
  el.replaceChildren();
  el.style.display = 'block';

  const labelEl = document.createElement('span');
  labelEl.className = 'vd-label';
  labelEl.textContent = 'Error';
  el.appendChild(labelEl);

  const msg = document.createElement('span');
  msg.textContent = message;
  el.appendChild(msg);
}

/* ---------- Extension status ---------- */

function updateExtensionStatus() {
  const statusEl = $('extensionStatus');
  const infoEl = $('extensionInfo');
  const installCard = $('installationCard');

  infoEl.replaceChildren();

  if (typeof window.nostr !== 'undefined') {
    statusEl.className = 'status-dot active';
    installCard.style.display = 'none';

    const line = document.createElement('div');
    line.className = 'status-line';

    const title = document.createElement('span');
    title.textContent = 'Podkey detected';
    line.appendChild(title);

    const badge = document.createElement('span');
    badge.className = 'badge badge-success';
    badge.textContent = 'Active';
    line.appendChild(badge);

    const meta = document.createElement('div');
    meta.className = 'status-meta';
    meta.textContent =
      'window.nostr is available for did:nostr and Solid authentication.';

    infoEl.appendChild(line);
    infoEl.appendChild(meta);

    log('Podkey extension detected — window.nostr is available', 'success');
  } else {
    statusEl.className = 'status-dot error';
    installCard.style.display = 'block';

    const line = document.createElement('div');
    line.className = 'status-line';

    const title = document.createElement('span');
    title.textContent = 'Podkey not found';
    line.appendChild(title);

    const badge = document.createElement('span');
    badge.className = 'badge badge-error';
    badge.textContent = 'Not installed';
    line.appendChild(badge);

    const meta = document.createElement('div');
    meta.className = 'status-meta';
    meta.textContent =
      'window.nostr is undefined. Install the extension to enable did:nostr and Solid support.';

    infoEl.appendChild(line);
    infoEl.appendChild(meta);

    log('Podkey extension not found — window.nostr is undefined', 'error');
  }
}

/* ---------- Tests ---------- */

function requireNostr() {
  if (!window.nostr) {
    throw new Error('window.nostr is not available');
  }
  return window.nostr;
}

async function testGetPublicKey() {
  log('Testing getPublicKey()…', 'info');
  try {
    const nostr = requireNostr();
    const pubkey = await nostr.getPublicKey();
    showResult('publicKeyResult', [
      ['Public key', pubkey],
      ['DID', `did:nostr:${pubkey}`]
    ]);
    log(`getPublicKey() succeeded: ${pubkey.substring(0, 16)}…`, 'success');
  } catch (error) {
    log(`getPublicKey() failed: ${error.message}`, 'error');
    showError('publicKeyResult', error.message);
  }
}

async function testKeypairStatus() {
  log('Testing keypair status…', 'info');
  try {
    const nostr = requireNostr();
    const pubkey = await nostr.getPublicKey();
    showResult('keypairStatusResult', [
      ['Status', 'Keypair exists'],
      ['Public key', `${pubkey.substring(0, 32)}…`],
      ['Length', `${pubkey.length} characters`]
    ]);
    log(`Keypair exists: ${pubkey.length}-char hex key`, 'success');
  } catch (error) {
    log(`Keypair check failed: ${error.message}`, 'error');
    showError('keypairStatusResult', error.message);
  }
}

async function testSignSimpleEvent() {
  log('Testing signEvent() with a simple event…', 'info');
  try {
    const nostr = requireNostr();
    const event = {
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: 'Hello from the Podkey test page!'
    };
    const signed = await nostr.signEvent(event);
    showPreformatted(
      'signEventResult',
      'Signed event',
      JSON.stringify(signed, null, 2)
    );
    log(`signEvent() succeeded — event id ${signed.id.substring(0, 16)}…`, 'success');
  } catch (error) {
    log(`signEvent() failed: ${error.message}`, 'error');
    showError('signEventResult', error.message);
  }
}

async function testSignTextNote() {
  log('Testing signEvent() with a text note…', 'info');
  try {
    const nostr = requireNostr();
    const event = {
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content:
        'This is a test note from the Podkey test page. Testing NIP-07 compatibility.'
    };
    const signed = await nostr.signEvent(event);
    log(`Text note signed — id ${signed.id.substring(0, 16)}…`, 'success');
    log(`Content: "${signed.content.substring(0, 50)}…"`, 'info');
  } catch (error) {
    log(`Text note signing failed: ${error.message}`, 'error');
  }
}

async function testSignWithTags() {
  log('Testing signEvent() with tags…', 'info');
  try {
    const nostr = requireNostr();
    const event = {
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['t', 'podkey'],
        ['t', 'test'],
        ['p', '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d']
      ],
      content: 'Testing event with tags #podkey #test'
    };
    const signed = await nostr.signEvent(event);
    log(`Event with tags signed — id ${signed.id.substring(0, 16)}…`, 'success');
    log(`Tags: ${signed.tags.length} included`, 'info');
  } catch (error) {
    log(`Tagged event signing failed: ${error.message}`, 'error');
  }
}

/* ---------- Wiring ---------- */

const ACTIONS = {
  getPublicKey: testGetPublicKey,
  keypairStatus: testKeypairStatus,
  signSimple: testSignSimpleEvent,
  signTextNote: testSignTextNote,
  signWithTags: testSignWithTags,
  clearLog
};

function wireActions() {
  document.querySelectorAll('[data-action]').forEach(btn => {
    const handler = ACTIONS[btn.dataset.action];
    if (handler) btn.addEventListener('click', handler);
  });
}

function init() {
  wireActions();
  log('Initialising test page…', 'info');
  setTimeout(updateExtensionStatus, 100);
}

window.addEventListener('nostr-ready', () => {
  log('nostr-ready event fired', 'success');
  updateExtensionStatus();
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// Re-check periodically in case the provider injects late.
setInterval(() => {
  if (typeof window.nostr === 'undefined') {
    const statusEl = $('extensionStatus');
    if (statusEl && statusEl.className.includes('active')) {
      updateExtensionStatus();
    }
  }
}, 2000);
