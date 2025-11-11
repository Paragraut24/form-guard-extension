// Popup UI logic with history, whitelist, blacklist - NO INLINE HANDLERS
let currentStats = {};

document.addEventListener('DOMContentLoaded', async () => {
  await loadStats();
  await loadHistory();
  await loadLists();
  setupEventListeners();
  setupTabs();
  
  // Listen for stats updates
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'statsUpdated') {
      updateStatsDisplay(request.stats);
    }
  });
});

async function loadStats() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getStats' });
    updateStatsDisplay(response);
  } catch (error) {
    console.error('Error loading stats:', error);
  }
}

function updateStatsDisplay(stats) {
  currentStats = stats;
  document.getElementById('totalScans').textContent = stats.totalScans || 0;
  document.getElementById('blocked').textContent = stats.blocked || 0;
  document.getElementById('warningsShown').textContent = stats.warningsShown || 0;
  document.getElementById('safe').textContent = stats.safe || 0;
}

async function loadHistory() {
  try {
    const history = await chrome.runtime.sendMessage({ 
      action: 'getHistory', 
      limit: 50 
    });
    
    displayHistory(history);
  } catch (error) {
    console.error('Error loading history:', error);
  }
}

function displayHistory(history) {
  const container = document.getElementById('historyList');
  
  if (!history || history.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📋</div>
        <p>No scan history yet</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = history.map((item, index) => {
    const status = item.result.status || 'unknown';
    const score = item.result.score || 0;
    const time = new Date(item.timestamp).toLocaleString();
    
    let badgeClass = 'badge-safe';
    let badgeText = 'Safe';
    
    if (status === 'malicious' || score >= 70) {
      badgeClass = 'badge-danger';
      badgeText = 'Malicious';
    } else if (status === 'suspicious' || score >= 40) {
      badgeClass = 'badge-warning';
      badgeText = 'Suspicious';
    }
    
    return `
      <div class="list-item" data-index="${index}">
        <div class="list-item-header">
          <div class="list-item-domain">${escapeHtml(item.domain)}</div>
          <div class="list-item-badge ${badgeClass}">${badgeText}</div>
        </div>
        <div class="list-item-info">
          Score: ${score}/100 • ${time}
        </div>
        <div class="list-item-actions">
          <button class="list-item-btn whitelist-from-history" data-domain="${escapeHtml(item.domain)}">
            Add to Whitelist
          </button>
          <button class="list-item-btn blacklist-from-history" data-domain="${escapeHtml(item.domain)}">
            Add to Blacklist
          </button>
        </div>
      </div>
    `;
  }).join('');
  
  // Add event listeners to buttons
  container.querySelectorAll('.whitelist-from-history').forEach(btn => {
    btn.addEventListener('click', () => addToWhitelistFromHistory(btn.dataset.domain));
  });
  
  container.querySelectorAll('.blacklist-from-history').forEach(btn => {
    btn.addEventListener('click', () => addToBlacklistFromHistory(btn.dataset.domain));
  });
}

async function loadLists() {
  try {
    const lists = await chrome.runtime.sendMessage({ action: 'getLists' });
    displayWhitelist(lists.whitelist || []);
    displayBlacklist(lists.blacklist || []);
  } catch (error) {
    console.error('Error loading lists:', error);
  }
}

function displayWhitelist(whitelist) {
  const container = document.getElementById('whitelistList');
  
  if (!whitelist || whitelist.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">✓</div>
        <p>No whitelisted domains</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = whitelist.map((domain, index) => `
    <div class="list-item" data-index="${index}">
      <div class="list-item-header">
        <div class="list-item-domain">${escapeHtml(domain)}</div>
        <div class="list-item-badge badge-safe">Trusted</div>
      </div>
      <div class="list-item-actions">
        <button class="list-item-btn remove-btn remove-whitelist" data-domain="${escapeHtml(domain)}">
          Remove
        </button>
      </div>
    </div>
  `).join('');
  
  // Add event listeners
  container.querySelectorAll('.remove-whitelist').forEach(btn => {
    btn.addEventListener('click', () => removeFromWhitelist(btn.dataset.domain));
  });
}

function displayBlacklist(blacklist) {
  const container = document.getElementById('blacklistList');
  
  if (!blacklist || blacklist.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">✗</div>
        <p>No blacklisted domains</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = blacklist.map((domain, index) => `
    <div class="list-item" data-index="${index}">
      <div class="list-item-header">
        <div class="list-item-domain">${escapeHtml(domain)}</div>
        <div class="list-item-badge badge-danger">Blocked</div>
      </div>
      <div class="list-item-actions">
        <button class="list-item-btn remove-btn remove-blacklist" data-domain="${escapeHtml(domain)}">
          Remove
        </button>
      </div>
    </div>
  `).join('');
  
  // Add event listeners
  container.querySelectorAll('.remove-blacklist').forEach(btn => {
    btn.addEventListener('click', () => removeFromBlacklist(btn.dataset.domain));
  });
}

function setupEventListeners() {
  document.getElementById('checkCurrentPage').addEventListener('click', checkCurrentPage);
  document.getElementById('openSettings').addEventListener('click', openSettings);
  document.getElementById('clearHistory').addEventListener('click', clearHistory);
  document.getElementById('addWhitelist').addEventListener('click', addWhitelistDomain);
  document.getElementById('addBlacklist').addEventListener('click', addBlacklistDomain);
}

function setupTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabName = button.dataset.tab;
      
      // Remove active class from all
      tabButtons.forEach(btn => btn.classList.remove('active'));
      tabContents.forEach(content => content.classList.remove('active'));
      
      // Add active class to clicked
      button.classList.add('active');
      document.getElementById(`${tabName}-tab`).classList.add('active');
    });
  });
}

async function checkCurrentPage() {
  const statusDisplay = document.getElementById('pageStatus');
  statusDisplay.className = 'page-status';
  statusDisplay.innerHTML = `
    <div class="status-icon">🔄</div>
    <div class="status-message">Analyzing...</div>
  `;
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url || tab.url.startsWith('chrome://')) {
      statusDisplay.innerHTML = `
        <div class="status-icon">❌</div>
        <div class="status-message">Cannot analyze this page</div>
      `;
      return;
    }
    
    const result = await chrome.runtime.sendMessage({
      action: 'analyzeURL',
      url: tab.url,
      context: { source: 'popup-check' }
    });
    
    displayResult(result);
    await loadStats();
    await loadHistory();
  } catch (error) {
    console.error('Check error:', error);
    statusDisplay.innerHTML = `
      <div class="status-icon">⚠️</div>
      <div class="status-message">Error analyzing page</div>
    `;
  }
}

function displayResult(result) {
  const statusDisplay = document.getElementById('pageStatus');
  let icon, message, className, details;
  
  switch (result.status) {
    case 'safe':
      icon = '✅';
      message = 'This page is safe';
      className = 'status-safe';
      details = `Risk Score: ${result.score}/100`;
      break;
    case 'suspicious':
      icon = '⚠️';
      message = 'This page is suspicious';
      className = 'status-warning';
      details = `Risk Score: ${result.score}/100`;
      break;
    case 'malicious':
      icon = '🚫';
      message = 'This page is dangerous';
      className = 'status-danger';
      details = `Risk Score: ${result.score}/100`;
      break;
    default:
      icon = '❓';
      message = 'Unknown status';
      className = '';
      details = '';
  }
  
  statusDisplay.className = `page-status ${className}`;
  statusDisplay.innerHTML = `
    <div class="status-icon">${icon}</div>
    <div class="status-message">${message}</div>
    ${details ? `<div class="status-details" style="display: block;">${details}</div>` : ''}
    ${result.vtDetections ? `<div class="status-details" style="display: block;">${result.vtDetections}/${result.vtEngines} vendors flagged this site</div>` : ''}
  `;
}

async function clearHistory() {
  if (confirm('Clear all scan history?')) {
    try {
      await chrome.runtime.sendMessage({ action: 'clearHistory' });
      await loadHistory();
    } catch (error) {
      console.error('Error clearing history:', error);
    }
  }
}

async function addWhitelistDomain() {
  const domain = prompt('Enter domain to whitelist (e.g., example.com):');
  if (domain && domain.trim()) {
    try {
      await chrome.runtime.sendMessage({ 
        action: 'addToWhitelist', 
        domain: domain.trim().toLowerCase()
      });
      await loadLists();
    } catch (error) {
      console.error('Error adding to whitelist:', error);
    }
  }
}

async function addBlacklistDomain() {
  const domain = prompt('Enter domain to blacklist (e.g., malicious.com):');
  if (domain && domain.trim()) {
    try {
      await chrome.runtime.sendMessage({ 
        action: 'addToBlacklist', 
        domain: domain.trim().toLowerCase()
      });
      await loadLists();
    } catch (error) {
      console.error('Error adding to blacklist:', error);
    }
  }
}

async function addToWhitelistFromHistory(domain) {
  try {
    await chrome.runtime.sendMessage({ 
      action: 'addToWhitelist', 
      domain 
    });
    await loadLists();
    // Switch to whitelist tab
    document.querySelector('.tab-btn[data-tab="whitelist"]').click();
  } catch (error) {
    console.error('Error:', error);
  }
}

async function addToBlacklistFromHistory(domain) {
  try {
    await chrome.runtime.sendMessage({ 
      action: 'addToBlacklist', 
      domain 
    });
    await loadLists();
    // Switch to blacklist tab
    document.querySelector('.tab-btn[data-tab="blacklist"]').click();
  } catch (error) {
    console.error('Error:', error);
  }
}

async function removeFromWhitelist(domain) {
  if (confirm(`Remove ${domain} from whitelist?`)) {
    try {
      await chrome.runtime.sendMessage({ 
        action: 'removeFromWhitelist', 
        domain 
      });
      await loadLists();
    } catch (error) {
      console.error('Error:', error);
    }
  }
}

async function removeFromBlacklist(domain) {
  if (confirm(`Remove ${domain} from blacklist?`)) {
    try {
      await chrome.runtime.sendMessage({ 
        action: 'removeFromBlacklist', 
        domain 
      });
      await loadLists();
    } catch (error) {
      console.error('Error:', error);
    }
  }
}

function openSettings() {
  chrome.runtime.openOptionsPage();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
