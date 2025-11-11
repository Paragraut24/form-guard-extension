export class DOMMonitor {
  constructor() {
    this.domSnapshots = new Map();
    this.suspiciousChanges = new Map();
  }
  
  // Track DOM changes on page
  startMonitoring(tabId, url) {
    console.log('👀 Monitoring DOM changes for:', url);
    
    // Send monitoring script to content
    chrome.tabs.executeScript(tabId, {
      code: `
        (function() {
          window.phishguardDOMChanges = [];
          
          // Track all DOM mutations
          const observer = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
              if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                const timestamp = Date.now();
                const addedHTML = Array.from(mutation.addedNodes)
                  .map(n => n.outerHTML || n.textContent)
                  .join('');
                
                window.phishguardDOMChanges.push({
                  type: 'element_added',
                  timestamp,
                  html: addedHTML.substring(0, 200),
                  parent: mutation.target.tagName
                });
              }
            });
          });
          
          observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: false
          });
          
          // Check for login buttons added via JavaScript
          setInterval(() => {
            const loginButtons = document.querySelectorAll('button[type="submit"]');
            loginButtons.forEach(btn => {
              if (!btn.dataset.phishguardTracked) {
                btn.dataset.phishguardTracked = true;
                window.phishguardDOMChanges.push({
                  type: 'login_button_detected',
                  timestamp: Date.now(),
                  text: btn.textContent
                });
              }
            });
          }, 1000);
        })();
      `
    });
  }
  
  // Analyze if DOM changes are suspicious
  async analyzeDOMChanges(tabId) {
    return new Promise((resolve) => {
      chrome.tabs.executeScript(tabId, {
        code: 'window.phishguardDOMChanges || []'
      }, (results) => {
        if (results && results[0]) {
          const changes = results[0];
          const riskScore = this.calculateDOMRisk(changes);
          resolve({ changes, riskScore });
        } else {
          resolve({ changes: [], riskScore: 0 });
        }
      });
    });
  }
  
  calculateDOMRisk(changes) {
    let score = 0;
    
    // Suspicious patterns
    const suspiciousPatterns = ['login', 'password', 'verify', 'confirm', 'update'];
    
    changes.forEach(change => {
      // Login button added dynamically = HIGH RISK
      if (change.type === 'login_button_detected') {
        score += 25;
      }
      
      // Suspicious content added to page
      const content = (change.html || '').toLowerCase();
      if (suspiciousPatterns.some(p => content.includes(p))) {
        score += 15;
      }
    });
    
    console.log('📊 DOM risk score:', score);
    return Math.min(score, 100);
  }
  
  // Get change history for a URL
  getChangeHistory(url) {
    return this.domSnapshots.get(url) || [];
  }
}
