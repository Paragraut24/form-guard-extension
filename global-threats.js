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
        <div class="empty-icon">🔍</div>
        <div class="empty-text">No threats found</div>
        <div class="empty-subtext">Try refreshing or adjusting filters</div>
      </div>
    `;
    return;
  }
  
  grid.innerHTML = threats.map(threat => `
    <div class="threat-card" data-target="${threat.target.toLowerCase()}">
      <div class="threat-header-row">
        <div class="threat-id">🚨 Threat #${threat.id}</div>
        <div class="threat-badge">${threat.status}</div>
      </div>
      
      <div class="threat-url-box">${escapeHtml(threat.url)}</div>
      
      <div class="threat-meta">
        <div class="meta-item">
          <span class="meta-icon">🎯</span>
          <span>Target: <strong>${threat.target}</strong></span>
        </div>
        <div class="meta-item">
          <span class="meta-icon">📅</span>
          <span>${threat.verified}</span>
        </div>
      </div>
      
      <div class="threat-actions">
        <button class="action-btn btn-scan" data-url="${escapeHtml(threat.url)}">
          <span>🔍</span>
          <span>Scan</span>
        </button>
        <button class="action-btn btn-block" data-url="${escapeHtml(threat.url)}">
          <span>🚫</span>
          <span>Block</span>
        </button>
        <button class="action-btn btn-report" data-url="${escapeHtml(threat.url)}">
          <span>📋</span>
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
      `🔍 PhishGuard Analysis\n\n` +
      `URL: ${url.substring(0, 60)}...\n\n` +
      `Score: ${result.score}/100\n` +
      `Status: ${result.status.toUpperCase()}\n` +
      `Reason: ${result.reason || 'Analysis complete'}`
    );
  } catch (error) {
    alert('❌ Failed to analyze URL');
  }
}

async function blockThreat(url) {
  try {
    const domain = new URL(url).hostname;
    
    const confirmed = confirm(
      `🚫 Block this domain?\n\n` +
      `Domain: ${domain}\n\n` +
      `This will add it to your blacklist.`
    );
    
    if (confirmed) {
      await chrome.runtime.sendMessage({ 
        action: 'addToBlacklist', 
        domain 
      });
      
      alert(`✅ ${domain} added to blacklist!`);
    }
  } catch (error) {
    alert('❌ Invalid URL format');
  }
}

function copyURL(url) {
  navigator.clipboard.writeText(url);
  alert('📋 URL copied to clipboard!');
}

function showError() {
  const grid = document.getElementById('threatsGrid');
  grid.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">❌</div>
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
