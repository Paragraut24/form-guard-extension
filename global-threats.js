// Global Threats Dashboard Logic
let allThreats = [];
let currentFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  loadThreats();
});

function setupEventListeners() {
  // Refresh button
  document.getElementById('refreshBtn').addEventListener('click', loadThreats);
  
  // Filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      filterThreats();
    });
  });
  
  // Event delegation for dynamically created threat buttons
  document.getElementById('threatsGrid').addEventListener('click', (e) => {
    const button = e.target.closest('button');
    if (!button) return;
    
    const url = button.dataset.url;
    if (!url) return;
    
    if (button.classList.contains('btn-scan')) {
      scanThreat(url);
    } else if (button.classList.contains('btn-block')) {
      blockThreat(url);
    } else if (button.classList.contains('btn-report')) {
      copyURL(url);
    } else if (button.classList.contains('retry-btn')) {
      loadThreats();
    }
  });
}

async function loadThreats() {
  const grid = document.getElementById('threatsGrid');
  
  grid.innerHTML = `
    <div class="loading-container">
      <div class="loading-spinner"></div>
      <div class="loading-text">Fetching latest threats...</div>
    </div>
  `;
  
  try {
    const response = await fetch('https://openphish.com/feed.txt');
    
    if (!response.ok) {
      throw new Error('API request failed');
    }
    
    const text = await response.text();
    const urls = text.split('\n').filter(url => url.trim()).slice(0, 30);
    
    allThreats = urls.map((url, index) => ({
      id: index + 1,
      url: url,
      target: detectTarget(url),
      verified: new Date().toLocaleString(),
      status: 'ONLINE'
    }));
    
    updateStats();
    displayThreats(allThreats);
    
  } catch (error) {
    console.error('Failed to load threats:', error);
    showError();
  }
}

function detectTarget(url) {
  const urlLower = url.toLowerCase();
  
  if (urlLower.includes('paypal') || urlLower.includes('payment')) return 'PayPal';
  if (urlLower.includes('bank') || urlLower.includes('chase') || urlLower.includes('wells')) return 'Banking';
  if (urlLower.includes('facebook') || urlLower.includes('instagram') || urlLower.includes('twitter')) return 'Social Media';
  if (urlLower.includes('amazon') || urlLower.includes('ebay')) return 'E-Commerce';
  if (urlLower.includes('microsoft') || urlLower.includes('office')) return 'Microsoft';
  if (urlLower.includes('apple') || urlLower.includes('icloud')) return 'Apple';
  if (urlLower.includes('netflix') || urlLower.includes('hulu')) return 'Streaming';
  
  return 'Various';
}

function updateStats() {
  document.getElementById('totalThreats').textContent = allThreats.length;
  document.getElementById('activeThreats').textContent = allThreats.filter(t => t.status === 'ONLINE').length;
  document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();
}

function displayThreats(threats) {
  const grid = document.getElementById('threatsGrid');
  
  if (!threats || threats.length === 0) {
    grid.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
               stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
        </div>
        <div class="empty-text">No threats found</div>
        <div class="empty-subtext">Try refreshing or adjusting filters</div>
      </div>
    `;
    return;
  }
  
  grid.innerHTML = threats.map(threat => `
    <div class="threat-card" data-target="${threat.target.toLowerCase()}">
      <div class="threat-header-row">
        <div class="threat-id">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          Threat #${threat.id}
        </div>
        <div class="threat-badge">${threat.status}</div>
      </div>
      
      <div class="threat-url-box">${escapeHtml(threat.url)}</div>
      
      <div class="threat-meta">
        <div class="meta-item">
          <span class="meta-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="22" y1="12" x2="18" y2="12"/>
              <line x1="6" y1="12" x2="2" y2="12"/>
              <line x1="12" y1="6" x2="12" y2="2"/>
              <line x1="12" y1="22" x2="12" y2="18"/>
            </svg>
          </span>
          <span>Target: <strong>${threat.target}</strong></span>
        </div>
        <div class="meta-item">
          <span class="meta-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
              <line x1="16" y1="2" x2="16" y2="6"/>
              <line x1="8" y1="2" x2="8" y2="6"/>
              <line x1="3" y1="10" x2="21" y2="10"/>
            </svg>
          </span>
          <span>${threat.verified}</span>
        </div>
      </div>
      
      <div class="threat-actions">
        <button class="action-btn btn-scan" data-url="${escapeHtml(threat.url)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
               stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <span>Scan</span>
        </button>
        <button class="action-btn btn-block" data-url="${escapeHtml(threat.url)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
               stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
          </svg>
          <span>Block</span>
        </button>
        <button class="action-btn btn-report" data-url="${escapeHtml(threat.url)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2"/>
            <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
          </svg>
          <span>Copy</span>
        </button>
      </div>
    </div>
  `).join('');
}

function filterThreats() {
  if (currentFilter === 'all') {
    displayThreats(allThreats);
    return;
  }
  
  const targetMap = {
    'banking': ['Banking', 'Chase', 'Wells Fargo'],
    'payment': ['PayPal', 'Payment'],
    'social': ['Social Media', 'Facebook', 'Instagram', 'Twitter']
  };
  
  const filtered = allThreats.filter(threat => {
    const targets = targetMap[currentFilter] || [];
    return targets.some(t => threat.target.includes(t));
  });
  
  displayThreats(filtered);
}

async function scanThreat(url) {
  try {
    const result = await chrome.runtime.sendMessage({ 
      action: 'analyzeURL', 
      url 
    });
    
    alert(
      `PhishGuard Analysis\n\n` +
      `URL: ${url.substring(0, 60)}...\n\n` +
      `Score: ${result.score}/100\n` +
      `Status: ${result.status.toUpperCase()}\n` +
      `Reason: ${result.reason || 'Analysis complete'}`
    );
  } catch (error) {
    alert('Failed to analyze URL');
  }
}

async function blockThreat(url) {
  try {
    const domain = new URL(url).hostname;
    
    const confirmed = confirm(
      `Block this domain?\n\n` +
      `Domain: ${domain}\n\n` +
      `This will add it to your blacklist.`
    );
    
    if (confirmed) {
      await chrome.runtime.sendMessage({ 
        action: 'addToBlacklist', 
        domain 
      });
      
      alert(`${domain} added to blacklist!`);
    }
  } catch (error) {
    alert('Invalid URL format');
  }
}

function copyURL(url) {
  navigator.clipboard.writeText(url);
  alert('URL copied to clipboard!');
}

function showError() {
  const grid = document.getElementById('threatsGrid');
  grid.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
             stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="15" y1="9" x2="9" y2="15"/>
          <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
      </div>
      <div class="empty-text">Failed to load global threats</div>
      <div class="empty-subtext">API may be rate-limited or temporarily unavailable</div>
      <button class="retry-btn">Try Again</button>
    </div>
  `;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
