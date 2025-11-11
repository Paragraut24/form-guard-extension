// blocked.js - Handles blocked page functionality

// Get URL parameters
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url');
const score = params.get('score') || '100';

console.log('=== BLOCKED PAGE LOADED ===');
console.log('Blocked URL:', blockedUrl);
console.log('Score:', score);

// Initialize page when DOM loads
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, initializing...');
  
  // Display URL
  const urlBox = document.getElementById('urlBox');
  if (urlBox) {
    urlBox.textContent = blockedUrl || 'Unknown URL';
  }
  
  // Display score
  const scoreValue = document.getElementById('scoreValue');
  if (scoreValue) {
    scoreValue.textContent = score + '/100';
  }
  
  // Display timestamp
  const timestamp = document.getElementById('timestamp');
  if (timestamp) {
    timestamp.textContent = new Date().toLocaleString();
  }
  
  // Setup event listeners
  setupEventListeners();
});

// Setup all button event listeners
function setupEventListeners() {
  const backBtn = document.getElementById('backBtn');
  const previewBtn = document.getElementById('previewBtn');
  const proceedBtn = document.getElementById('proceedBtn');
  
  if (backBtn) {
    backBtn.addEventListener('click', goBack);
    console.log('✓ Back button listener added');
  }
  
  if (previewBtn) {
    previewBtn.addEventListener('click', openSafePreview);
    console.log('✓ Preview button listener added');
  }
  
  if (proceedBtn) {
    proceedBtn.addEventListener('click', proceedAnyway);
    console.log('✓ Proceed button listener added');
  }
}

// Go back to previous safe page
function goBack() {
  console.log('Going back to safety...');
  
  // Go to a safe page instead of history.back() which might trigger block again
  window.location.href = 'https://www.google.com';
}

// Open safe preview in new window using preview.html
function openSafePreview() {
  console.log('Opening safe preview for:', blockedUrl);
  
  if (!blockedUrl) {
    alert('⚠️ No URL to preview');
    return;
  }
  
  // Create URL for preview page
  const previewUrl = chrome.runtime.getURL('preview.html') + '?url=' + encodeURIComponent(blockedUrl);
  
  console.log('Preview URL:', previewUrl);
  
  // Open in new window
  const previewWindow = window.open(
    previewUrl,
    'PhishGuardPreview',
    'width=1200,height=800,menubar=no,toolbar=no,location=no,status=no,scrollbars=yes,resizable=yes'
  );
  
  if (!previewWindow) {
    alert('❌ Could not open preview window.\n\nPlease allow popups for this extension:\n1. Click the popup blocker icon in address bar\n2. Select "Always allow popups from this extension"\n3. Try again');
    return;
  }
  
  console.log('✓ Preview window opened successfully');
}


// Proceed anyway with double confirmation and whitelisting
async function proceedAnyway() {
  console.log('User attempting to proceed to:', blockedUrl);
  
  if (!blockedUrl) {
    alert('❌ No URL to proceed to');
    return;
  }
  
  // First warning
  const confirmed = confirm(
    '⚠️ WARNING - DANGEROUS SITE\n\n' +
    'This site has been identified as MALICIOUS (Score: ' + score + '/100)\n\n' +
    'Proceeding may result in:\n' +
    '• Identity theft\n' +
    '• Malware infection\n' +
    '• Financial fraud\n' +
    '• Data theft\n\n' +
    'Are you sure you want to continue?'
  );
  
  if (!confirmed) {
    console.log('User cancelled at first warning');
    return;
  }
  
  // Second warning
  const doubleConfirm = confirm(
    '🚨 FINAL WARNING\n\n' +
    'You are about to visit:\n' + blockedUrl + '\n\n' +
    'PhishGuard will temporarily whitelist this site.\n' +
    'You will NOT be protected on this visit.\n\n' +
    'Type YES in your mind and click OK if you are ABSOLUTELY CERTAIN.'
  );
  
  if (!doubleConfirm) {
    console.log('User cancelled at final warning');
    return;
  }
  
  console.log('User confirmed - adding to temporary whitelist and proceeding');
  
  try {
    // Extract domain from URL
    const urlObj = new URL(blockedUrl);
    const domain = urlObj.hostname;
    
    console.log('Adding to whitelist:', domain);
    
    // Add to whitelist via background script
    const response = await chrome.runtime.sendMessage({
      action: 'addToWhitelist',
      domain: domain
    });
    
    console.log('Whitelist response:', response);
    
    // Wait a moment for whitelist to be saved
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Now navigate to the site
    console.log('Navigating to:', blockedUrl);
    window.location.replace(blockedUrl);
    
  } catch (error) {
    console.error('Error whitelisting domain:', error);
    alert('❌ Error: Could not whitelist domain. Try again.');
  }
}
