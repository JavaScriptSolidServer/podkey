/**
 * Podkey - Signing Approval Popup
 * Presents signing requests to the user for explicit approval/denial.
 *
 * Security contract (must stay byte-equivalent in effect):
 *   - Read requestId/origin/action/preview from the query string.
 *   - On a choice: chrome.runtime.sendMessage(
 *       { type: 'APPROVE_SIGNING', requestId, approved: <bool> }).
 *   - Closing the popup (beforeunload) sends approved:false (closing = deny).
 *   - A 60-second auto-deny countdown denies if the user does nothing.
 *
 * The displayed origin and payload come from web pages and are treated as
 * hostile strings: only ever written via textContent, never innerHTML.
 */

const APPROVAL_TIMEOUT_MS = 60_000;

const params = new URLSearchParams(window.location.search);
const requestId = params.get('id');
const origin = params.get('origin') || 'Unknown';
const action = params.get('action') || 'sign';
const preview = params.get('preview') || '';

// One-shot guard: the decision is sent exactly once, whichever path fires
// first (button click, auto-deny timeout, or window close).
let decisionSent = false;

function sendDecision(approved) {
  if (decisionSent) return;
  decisionSent = true;
  chrome.runtime.sendMessage({
    type: 'APPROVE_SIGNING',
    requestId,
    approved
  });
}

// ---- Populate UI (textContent only — never innerHTML for untrusted data) ----

document.getElementById('origin').textContent = origin;
document.getElementById('action').textContent = action;

const previewEl = document.getElementById('preview');
const previewWrap = document.getElementById('previewWrap');
if (preview) {
  try {
    // Pretty-print JSON payloads for readability; fall back to raw text.
    const parsed = JSON.parse(preview);
    previewEl.textContent = JSON.stringify(parsed, null, 2);
  } catch {
    previewEl.textContent = preview;
  }
} else {
  previewWrap.style.display = 'none';
}

// ---- Buttons ----

document.getElementById('approve').addEventListener('click', () => {
  sendDecision(true);
  window.close();
});

document.getElementById('deny').addEventListener('click', () => {
  sendDecision(false);
  window.close();
});

// Closing the popup without choosing is a denial.
window.addEventListener('beforeunload', () => {
  sendDecision(false);
});

// ---- 60-second auto-deny countdown ----

const countdownEl = document.getElementById('countdown');
const barEl = document.getElementById('timeoutBar');
const startedAt = Date.now();

function tickCountdown() {
  if (decisionSent) return;

  const elapsed = Date.now() - startedAt;
  const remainingMs = Math.max(0, APPROVAL_TIMEOUT_MS - elapsed);
  const remainingSec = Math.ceil(remainingMs / 1000);
  const fraction = remainingMs / APPROVAL_TIMEOUT_MS;

  countdownEl.textContent = String(remainingSec);
  barEl.style.width = `${(fraction * 100).toFixed(2)}%`;
  barEl.classList.toggle('urgent', remainingSec <= 10);

  if (remainingMs <= 0) {
    // Time is up: deny and close.
    sendDecision(false);
    window.close();
    return;
  }

  requestAnimationFrame(tickCountdown);
}

requestAnimationFrame(tickCountdown);
