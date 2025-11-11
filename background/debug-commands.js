// Manual testing commands - run in service worker console

// Test URL analysis
window.testAnalyze = async (url) => {
  console.log('Testing URL:', url);
  try {
    const result = await chrome.runtime.sendMessage({
      action: 'analyzeURL',
      url: url
    });
    console.log('Result:', result);
  } catch (e) {
    console.error('Error:', e);
  }
};

// Test blocking
window.testBlock = (url) => {
  console.log('Testing block for:', url);
  chrome.tabs.update({
    url: chrome.runtime.getURL('blocked.html') + 
         '?url=' + encodeURIComponent(url) +
         '&reason=test'
  });
};

// Check stats
window.checkStats = async () => {
  const data = await chrome.storage.local.get('stats');
  console.log('Stats:', data);
};

// Check settings
window.checkSettings = async () => {
  const data = await chrome.storage.sync.get(null);
  console.log('Settings:', data);
};

// Clear history
window.clearAllHistory = async () => {
  await chrome.storage.local.set({ history: [] });
  console.log('✓ History cleared');
};
