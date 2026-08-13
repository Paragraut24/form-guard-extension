// ============ PHISHGUARD SERVICE WORKER ============

// Import security modules
import { SecureStorage } from './secure-storage.js';
import { MessageSecurity } from './message-security.js';

// Initialize security modules
const secureStorage = new SecureStorage();
const messageSecurity = new MessageSecurity();

const PHISHING_INDICATORS = {
  free_hosting: ['weebly.com', 'wixsite.com', 'wordpress.com', 'blogspot.com', 'tumblr.com', 'square.site'],
  suspicious_tlds: ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.top', '.xyz', '.club'],
  suspicious_keywords: ['login', 'verify', 'confirm', 'account', 'security', 'update', 'banking', 'paypal', 'signin', 'password']
};

const TRUSTED_DOMAINS = [
  'google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'linkedin.com',
  'github.com', 'stackoverflow.com', 'amazon.com', 'netflix.com', 'spotify.com',
  'microsoft.com', 'apple.com', 'reddit.com', 'wikipedia.org', 'instagram.com'
];

console.log('✅ PhishGuard Service Worker Started');

// Show consent screen on first install
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.storage.local.get('consent_given', (data) => {
      if (!data.consent_given) {
        chrome.tabs.create({ url: chrome.runtime.getURL('consent.html') });
      }
    });
  }
});

// ============ MESSAGE HANDLER ============
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('📨 Message received:', request.action);
  
  // Security validation
  const securityCheck = messageSecurity.validateMessage(request, sender);
  if (!securityCheck.allowed) {
    console.warn('❌ Message rejected:', securityCheck.error);
    sendResponse({ error: securityCheck.error, blocked: true });
    return true;
  }
  
  if (request.action === 'analyzeURL') {
    analyzeURL(request.url)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }
  
  if (request.action === 'getStats') {
    getStats().then(stats => sendResponse(stats));
    return true;
  }
  
  if (request.action === 'getHistory') {
    getHistory(request.limit || 50).then(history => sendResponse(history));
    return true;
  }
  
  if (request.action === 'clearHistory') {
    chrome.storage.local.set({ history: [] });
    sendResponse({ success: true});
    return true;
  }
  
  if (request.action === 'addToWhitelist') {
    addToWhitelist(request.domain).then(() => sendResponse({ success: true }));
    return true;
  }
  
  if (request.action === 'removeFromWhitelist') {
    removeFromWhitelist(request.domain).then(() => sendResponse({ success: true }));
    return true;
  }
  
  if (request.action === 'addToBlacklist') {
    addToBlacklist(request.domain).then(() => sendResponse({ success: true }));
    return true;
  }
  
  if (request.action === 'removeFromBlacklist') {
    removeFromBlacklist(request.domain).then(() => sendResponse({ success: true }));
    return true;
  }
  
  if (request.action === 'getLists') {
    getLists().then(lists => sendResponse(lists));
    return true;
  }
});

// ============ MAIN ANALYSIS FUNCTION ============
async function analyzeURL(url) {
  try {
    const settings = await loadSettings();
    console.log('🔍 Analyzing:', url);
    
    const domain = new URL(url).hostname;
    
    // Check whitelist
    if (await isWhitelisted(domain, settings.whitelist)) {
      console.log('✅ Whitelisted');
      const result = { status: 'safe', score: 0, reason: 'whitelisted' };
      await addToHistory(url, result);
      await updateStats('safe');
      return result;
    }
    
    // Check blacklist
    if (await isBlacklisted(domain, settings.blacklist)) {
      console.log('🚫 Blacklisted');
      const result = { status: 'malicious', score: 100, reason: 'blacklisted' };
      await addToHistory(url, result);
      await updateStats('malicious');
      return result;
    }
    
    // Check trusted domains
    if (isTrustedDomain(domain)) {
      console.log('✅ Trusted domain');
      const result = { status: 'safe', score: 0, reason: 'trusted_domain' };
      await addToHistory(url, result);
      await updateStats('safe');
      return result;
    }
    
    // Check phishing indicators
    const indicatorScore = checkPhishingIndicators(url, domain);
    console.log('📊 Phishing indicators score:', indicatorScore);
    
    // If already high risk, mark as malicious
    if (indicatorScore >= 70) {
      console.log('🚫 HIGH RISK - Marking as malicious');
      const result = { status: 'malicious', score: indicatorScore, reason: 'phishing_indicators' };
      await addToHistory(url, result);
      await updateStats('malicious');
      return result;
    }
    
    // If no API key, return indicator score
    if (!settings.apiKey) {
      console.log('⚠️ No API key - using indicator score');
      const status = indicatorScore >= 40 ? 'suspicious' : 'safe';
      const result = { status, score: indicatorScore, reason: 'no_api_key' };
      await addToHistory(url, result);
      await updateStats(status);
      return result;
    }
    
    // Call VirusTotal
    console.log('🌐 Calling VirusTotal API...');
    const vtResult = await callVirusTotal(url, settings.apiKey);
    console.log('✅ VirusTotal result:', vtResult);
    
    // Combine scores
    const finalScore = Math.round((indicatorScore * 0.3) + (vtResult.score * 0.7));
    const status = finalScore >= 70 ? 'malicious' : finalScore >= 40 ? 'suspicious' : 'safe';
    
    const result = {
      status,
      score: finalScore,
      indicatorScore,
      vtScore: vtResult.score,
      vtDetections: vtResult.detections,
      reason: 'combined_analysis'
    };
    
    await addToHistory(url, result);
    await updateStats(status);
    
    return result;
    
  } catch (error) {
    console.error('❌ Analysis error:', error);
    return { error: error.message, status: 'error', score: 0 };
  }
}

// ============ PHISHING INDICATORS CHECK ============
function checkPhishingIndicators(url, domain) {
  let score = 0;
  const urlLower = url.toLowerCase();
  
  // Free hosting
  if (PHISHING_INDICATORS.free_hosting.some(h => domain.endsWith(h))) {
    score += 35;
  }
  
  // Suspicious TLD
  if (PHISHING_INDICATORS.suspicious_tlds.some(tld => domain.endsWith(tld))) {
    score += 30;
  }
  
  // Suspicious keywords
  const keywordCount = PHISHING_INDICATORS.suspicious_keywords.filter(kw => urlLower.includes(kw)).length;
  score += keywordCount * 10;
  
  // No HTTPS
  if (!url.startsWith('https://')) {
    score += 25;
  }
  
  // IP address
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
    score += 40;
  }
  
  // @ symbol
  if (url.includes('@')) {
    score += 20;
  }
  
  // Long domain
  if (domain.length > 40) {
    score += 15;
  }
  
  // Many subdomains
  if (domain.split('.').length > 4) {
    score += 15;
  }
  
  return Math.min(score, 100);
}

// ============ VIRUSTOTAL API CALL ============
async function callVirusTotal(url, apiKey) {
  try {
    const response = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: 'url=' + encodeURIComponent(url)
    });
    
    if (!response.ok) {
      throw new Error('VirusTotal API error: ' + response.status);
    }
    
    const data = await response.json();
    const analysisId = data.data.id;
    
    // Wait 5 seconds for analysis
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Get analysis results
    const analysisResponse = await fetch(
      'https://www.virustotal.com/api/v3/analyses/' + analysisId,
      { headers: { 'x-apikey': apiKey } }
    );
    
    if (!analysisResponse.ok) {
      throw new Error('VirusTotal analysis error');
    }
    
    const analysisData = await analysisResponse.json();
    const stats = analysisData.data.attributes.stats;
    const totalEngines = stats.malicious + stats.undetected + stats.suspicious + stats.harmless;
    const score = totalEngines > 0 ? Math.round((stats.malicious / totalEngines) * 100) : 0;
    
    return {
      score,
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      detections: stats.malicious + stats.suspicious,
      totalEngines
    };
  } catch (error) {
    console.error('VirusTotal error:', error);
    return { score: 0, malicious: 0, suspicious: 0, detections: 0, totalEngines: 0 };
  }
}

// ============ HELPER FUNCTIONS ============
function isTrustedDomain(domain) {
  const domainLower = domain.toLowerCase();
  return TRUSTED_DOMAINS.some(td => domainLower === td || domainLower === 'www.' + td || domainLower.endsWith('.' + td));
}

async function isWhitelisted(domain, whitelist) {
  // Fixed: Exact domain matching only (no substring bypass)
  return whitelist.some(w => {
    const whitelistDomain = w.toLowerCase();
    const checkDomain = domain.toLowerCase();
    // Exact match or proper subdomain
    return checkDomain === whitelistDomain || checkDomain.endsWith('.' + whitelistDomain);
  });
}

async function isBlacklisted(domain, blacklist) {
  // Fixed: Exact domain matching only
  return blacklist.some(b => {
    const blacklistDomain = b.toLowerCase();
    const checkDomain = domain.toLowerCase();
    return checkDomain === blacklistDomain || checkDomain.endsWith('.' + blacklistDomain);
  });
}

async function loadSettings() {
  // Use secure storage for API key
  const apiKey = await secureStorage.getApiKey();
  
  const settings = await chrome.storage.sync.get({
    whitelist: [],
    blacklist: [],
    showNotifications: true
  });
  
  return {
    apiKey: apiKey || '',
    whitelist: settings.whitelist,
    blacklist: settings.blacklist,
    showNotifications: settings.showNotifications
  };
}

async function addToHistory(url, result) {
  const data = await chrome.storage.local.get('history');
  const history = data.history || [];
  
  history.unshift({
    url,
    domain: new URL(url).hostname,
    result,
    timestamp: Date.now()
  });
  
  await chrome.storage.local.set({ history: history.slice(0, 100) });
}

async function updateStats(status) {
  const data = await chrome.storage.local.get('stats');
  const stats = data.stats || { totalScans: 0, malicious: 0, suspicious: 0, safe: 0 };
  
  stats.totalScans++;
  if (status === 'malicious') stats.malicious++;
  else if (status === 'suspicious') stats.suspicious++;
  else stats.safe++;
  
  await chrome.storage.local.set({ stats });
}

async function getStats() {
  const data = await chrome.storage.local.get('stats');
  return data.stats || { totalScans: 0, malicious: 0, suspicious: 0, safe: 0 };
}

async function getHistory(limit) {
  const data = await chrome.storage.local.get('history');
  return (data.history || []).slice(0, limit);
}

async function addToWhitelist(domain) {
  const settings = await loadSettings();
  if (!settings.whitelist.includes(domain)) {
    settings.whitelist.push(domain);
    await chrome.storage.sync.set({ whitelist: settings.whitelist });
  }
}

async function removeFromWhitelist(domain) {
  const settings = await loadSettings();
  await chrome.storage.sync.set({ whitelist: settings.whitelist.filter(d => d !== domain) });
}

async function addToBlacklist(domain) {
  const settings = await loadSettings();
  if (!settings.blacklist.includes(domain)) {
    settings.blacklist.push(domain);
    await chrome.storage.sync.set({ blacklist: settings.blacklist });
  }
}

async function removeFromBlacklist(domain) {
  const settings = await loadSettings();
  await chrome.storage.sync.set({ blacklist: settings.blacklist.filter(d => d !== domain) });
}

async function getLists() {
  const settings = await loadSettings();
  return {
    whitelist: settings.whitelist || [],
    blacklist: settings.blacklist || []
  };
}

// ============ AUTO-SCAN PAGES ============
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0 || details.url.startsWith('chrome://') || details.url.startsWith('chrome-extension://')) return;
  
  console.log('📄 Page loaded:', details.url);
  
  try {
    const result = await analyzeURL(details.url);
    
    if (result.status === 'malicious' || result.score >= 70) {
      console.log('🛑 BLOCKING malicious page, score:', result.score);
      
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('blocked.html') + 
             '?url=' + encodeURIComponent(details.url) + 
             '&score=' + result.score
      });
      
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: '🛡️ PhishGuard - Threat Blocked',
        message: `Blocked: ${new URL(details.url).hostname}\nScore: ${result.score}/100`
      });
    }
  } catch (error) {
    console.error('Auto-scan error:', error);
  }
}, { url: [{ schemes: ['http', 'https'] }] });

console.log('✅ Service Worker fully loaded');

// Cleanup inactive rate limiters every 5 minutes
setInterval(() => {
  messageSecurity.cleanup();
}, 5 * 60 * 1000);

// Check for API key rotation on startup
secureStorage.needsKeyRotation().then(needsRotation => {
  if (needsRotation) {
    console.warn('⚠️ API key rotation recommended (>90 days old)');
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: '🔑 PhishGuard - API Key Rotation',
      message: 'Your VirusTotal API key is over 90 days old. Consider rotating it for security.'
    });
  }
});
