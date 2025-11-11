// Options page logic
document.addEventListener('DOMContentLoaded', async () => {
  // Load existing settings
  const data = await chrome.storage.sync.get([
    'apiKey', 
    'sensitivity', 
    'privacyMode',
    'showNotifications'
  ]);
  
  if (data.apiKey) document.getElementById('apiKey').value = data.apiKey;
  if (data.sensitivity) document.getElementById('sensitivity').value = data.sensitivity;
  if (data.privacyMode) document.getElementById('privacyMode').checked = data.privacyMode;
  if (data.showNotifications !== undefined) {
    document.getElementById('showNotifications').checked = data.showNotifications;
  }
  
  // Save button
  document.getElementById('save').addEventListener('click', async () => {
    const settings = {
      apiKey: document.getElementById('apiKey').value,
      sensitivity: document.getElementById('sensitivity').value,
      privacyMode: document.getElementById('privacyMode').checked,
      showNotifications: document.getElementById('showNotifications').checked,
      whitelist: data.whitelist || [],
      blacklist: data.blacklist || []
    };
    
    await chrome.storage.sync.set(settings);
    
    const statusEl = document.getElementById('status');
    statusEl.className = 'success';
    statusEl.textContent = '✓ Settings saved successfully!';
    
    setTimeout(() => {
      statusEl.style.display = 'none';
    }, 3000);
  });
  
  // Reset button
  document.getElementById('reset').addEventListener('click', async () => {
    if (confirm('Reset all settings to defaults?')) {
      document.getElementById('apiKey').value = '';
      document.getElementById('sensitivity').value = 'medium';
      document.getElementById('privacyMode').checked = false;
      document.getElementById('showNotifications').checked = true;
      
      const statusEl = document.getElementById('status');
      statusEl.className = 'success';
      statusEl.textContent = '✓ Settings reset to defaults';
      
      setTimeout(() => {
        statusEl.style.display = 'none';
      }, 3000);
    }
  });
});
    