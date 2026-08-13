// Options page logic with secure API key storage
import { SecureStorage } from '../background/secure-storage.js';

const secureStorage = new SecureStorage();

document.addEventListener('DOMContentLoaded', async () => {
  // Load existing settings
  const apiKey = await secureStorage.getApiKey();
  const data = await chrome.storage.sync.get([
    'sensitivity', 
    'privacyMode',
    'showNotifications'
  ]);
  
  // Show masked API key if exists
  if (apiKey) {
    document.getElementById('apiKey').value = apiKey;
    document.getElementById('apiKey').setAttribute('placeholder', '••••••••••••••••' + apiKey.slice(-8));
  }
  
  if (data.sensitivity) document.getElementById('sensitivity').value = data.sensitivity;
  if (data.privacyMode) document.getElementById('privacyMode').checked = data.privacyMode;
  if (data.showNotifications !== undefined) {
    document.getElementById('showNotifications').checked = data.showNotifications;
  }
  
  // Check if key rotation needed
  const needsRotation = await secureStorage.needsKeyRotation();
  if (needsRotation) {
    showRotationWarning();
  }
  
  // Save button
  document.getElementById('save').addEventListener('click', async () => {
    const apiKeyValue = document.getElementById('apiKey').value.trim();
    
    // Validate API key format if provided
    if (apiKeyValue && !secureStorage.validateApiKey(apiKeyValue)) {
      showError('Invalid API key format. VirusTotal keys are 64-character hexadecimal strings.');
      return;
    }
    
    // Store API key securely
    if (apiKeyValue) {
      try {
        await secureStorage.storeApiKey(apiKeyValue);
      } catch (error) {
        showError('Failed to store API key: ' + error.message);
        return;
      }
    }
    
    // Store other settings
    const settings = {
      sensitivity: document.getElementById('sensitivity').value,
      privacyMode: document.getElementById('privacyMode').checked,
      showNotifications: document.getElementById('showNotifications').checked,
      whitelist: data.whitelist || [],
      blacklist: data.blacklist || []
    };
    
    await chrome.storage.sync.set(settings);
    
    showSuccess('✓ Settings saved successfully! API key encrypted and stored securely.');
  });
  
  // Reset button
  document.getElementById('reset').addEventListener('click', async () => {
    if (confirm('Reset all settings to defaults? This will clear your API key.')) {
      await secureStorage.clearSecureData();
      
      document.getElementById('apiKey').value = '';
      document.getElementById('sensitivity').value = 'medium';
      document.getElementById('privacyMode').checked = false;
      document.getElementById('showNotifications').checked = true;
      
      showSuccess('✓ Settings reset to defaults');
    }
  });
});

function showSuccess(message) {
  const statusEl = document.getElementById('status');
  statusEl.className = 'success';
  statusEl.style.display = 'block';
  statusEl.textContent = message;
  
  setTimeout(() => {
    statusEl.style.display = 'none';
  }, 3000);
}

function showError(message) {
  const statusEl = document.getElementById('status');
  statusEl.className = 'error';
  statusEl.style.display = 'block';
  statusEl.textContent = '❌ ' + message;
  
  setTimeout(() => {
    statusEl.style.display = 'none';
  }, 5000);
}

function showRotationWarning() {
  const warningDiv = document.createElement('div');
  warningDiv.className = 'warning';
  warningDiv.innerHTML = `
    <strong>⚠️ Security Notice:</strong> Your API key is over 90 days old. 
    Consider rotating it for better security.
  `;
  warningDiv.style.cssText = `
    background: #fff3cd;
    border: 1px solid #ffc107;
    padding: 12px;
    margin-bottom: 20px;
    border-radius: 4px;
  `;
  
  const form = document.querySelector('.settings-form');
  form.insertBefore(warningDiv, form.firstChild);
}
