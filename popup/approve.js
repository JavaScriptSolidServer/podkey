/**
 * Podkey - Signing Approval Popup
 * Presents signing requests to the user for explicit approval/denial.
 */

const params = new URLSearchParams(window.location.search);
const requestId = params.get('id');
const origin = params.get('origin') || 'Unknown';
const action = params.get('action') || 'sign';
const preview = params.get('preview') || '';

// Populate UI
document.getElementById('origin').textContent = origin;
document.getElementById('action').textContent = `wants to: ${action}`;

if (preview) {
  try {
    // Try to pretty-print JSON previews
    const parsed = JSON.parse(preview);
    document.getElementById('preview').textContent = JSON.stringify(parsed, null, 2);
  } catch {
    document.getElementById('preview').textContent = preview;
  }
} else {
  document.getElementById('preview').style.display = 'none';
}

// Approve button
document.getElementById('approve').addEventListener('click', () => {
  chrome.runtime.sendMessage({
    type: 'APPROVE_SIGNING',
    requestId,
    approved: true
  });
  window.close();
});

// Deny button
document.getElementById('deny').addEventListener('click', () => {
  chrome.runtime.sendMessage({
    type: 'APPROVE_SIGNING',
    requestId,
    approved: false
  });
  window.close();
});

// Also deny on window close (user closes the popup without clicking)
window.addEventListener('beforeunload', () => {
  chrome.runtime.sendMessage({
    type: 'APPROVE_SIGNING',
    requestId,
    approved: false
  });
});
