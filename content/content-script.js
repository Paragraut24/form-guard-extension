// Content script for DOM monitoring and interception
(function() {
  'use strict';
  
  let checkedLinks = new Set();
  let isAnalyzing = false;
  
  console.log('🔍 PhishGuard content script loaded');
  
  // Initialize
  init();
  
  function init() {
    console.log('✓ Initializing content script');
    monitorLinks();
    observeDOM();
    interceptForms();
    initClipboardMonitoring();
    console.log('✓ Content script ready');
  }
  
  // ============ LINK MONITORING ============
  function monitorLinks() {
    document.addEventListener('mouseover', handleLinkHover, true);
    document.addEventListener('click', handleLinkClick, true);
  }
  
  function handleLinkHover(event) {
    try {
      const link = event.target.closest('a');
      if (!link || !link.href) return;
      
      const url = link.href;
      if (checkedLinks.has(url)) return;
      
      const quickCheck = performQuickCheck(url);
      
      if (quickCheck.suspicious) {
        addVisualWarning(link, 'suspicious');
        checkedLinks.add(url);
      }
    } catch (error) {
      console.error('Hover error:', error);
    }
  }
  
  function handleLinkClick(event) {
    try {
      const link = event.target.closest('a');
      if (!link || !link.href) return;
      
      const url = link.href;
      
      const quickCheck = performQuickCheck(url);
      
      if (quickCheck.score > 40) {
        event.preventDefault();
        event.stopPropagation();
        
        showAnalyzingIndicator(link);
        
        // Send to background for full analysis
        chrome.runtime.sendMessage({
          action: 'analyzeURL',
          url: url,
          context: { source: 'link-click' }
        }, (result) => {
          hideAnalyzingIndicator();
          
          if (chrome.runtime.lastError) {
            console.error('Message error:', chrome.runtime.lastError);
            return;
          }
          
          if (!result) {
            console.error('No result from background');
            return;
          }
          
          if (result.status === 'malicious' || result.status === 'suspicious') {
            showBlockingModal(url, result);
          } else if (result.status === 'safe') {
            window.location.href = url;
          }
        });
      }
    } catch (error) {
      console.error('Click error:', error);
    }
  }
  
  // ============ QUICK CLIENT-SIDE CHECK ============
  function performQuickCheck(url) {
    try {
      const urlObj = new URL(url);
      let score = 0;
      const reasons = [];
      
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)) {
        score += 30;
        reasons.push('Uses IP address instead of domain');
      }
      
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
      if (suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld))) {
        score += 25;
        reasons.push('Suspicious top-level domain');
      }
      
      if (urlObj.protocol !== 'https:') {
        score += 15;
        reasons.push('Non-secure connection');
      }
      
      if (url.length > 100) {
        score += 10;
        reasons.push('Unusually long URL');
      }
      
      if (/%[0-9A-Fa-f]{2}/.test(url)) {
        score += 10;
        reasons.push('Contains encoded characters');
      }
      
      if (url.includes('@')) {
        score += 25;
        reasons.push('Contains @ symbol');
      }
      
      return {
        suspicious: score > 30,
        score,
        reasons
      };
    } catch {
      return { suspicious: false, score: 0, reasons: [] };
    }
  }
  
  // ============ VISUAL WARNING ============
  function addVisualWarning(element, level) {
    try {
      element.classList.add('phishguard-warning');
      element.classList.add(`phishguard-${level}`);
      
      const tooltip = document.createElement('div');
      tooltip.className = 'phishguard-tooltip';
      tooltip.textContent = '⚠️ Suspicious link';
      element.appendChild(tooltip);
    } catch (error) {
      console.error('Warning error:', error);
    }
  }
  
  // ============ BLOCKING MODAL ============
  function showBlockingModal(url, result) {
    try {
      const modal = document.createElement('div');
      modal.id = 'phishguard-modal';
      modal.innerHTML = `
        <div class="phishguard-modal-content">
          <div class="phishguard-modal-header">
            <span class="phishguard-icon">🛡️</span>
            <h2>Potentially Dangerous Website Blocked</h2>
          </div>
          <div class="phishguard-modal-body">
            <p class="phishguard-url">${escapeHtml(url)}</p>
            <p class="phishguard-risk-score">Risk Score: <strong>${result.score}/100</strong></p>
            <p class="phishguard-reason">${getReasonText(result)}</p>
            ${result.vtDetections ? `<p class="phishguard-detections">${result.vtDetections}/${result.vtEngines} security vendors flagged this site</p>` : ''}
          </div>
          <div class="phishguard-modal-actions">
            <button id="phishguard-close" class="phishguard-btn phishguard-btn-primary">
              Go Back (Recommended)
            </button>
            <button id="phishguard-proceed" class="phishguard-btn phishguard-btn-danger">
              Proceed Anyway (Not Recommended)
            </button>
          </div>
        </div>
      `;
      
      document.body.appendChild(modal);
      
      document.getElementById('phishguard-close').addEventListener('click', () => {
        modal.remove();
      });
      
      document.getElementById('phishguard-proceed').addEventListener('click', () => {
        modal.remove();
        window.location.href = url;
      });
    } catch (error) {
      console.error('Modal error:', error);
    }
  }
  
  // ============ FORM INTERCEPTION ============
  function interceptForms() {
    document.addEventListener('submit', async (event) => {
      try {
        const form = event.target;
        if (!form || form.tagName !== 'FORM') return;
        
        console.log('📋 Form submitted, analyzing...');
        
        const formData = analyzeForm(form);
        
        if (formData.suspicious) {
          event.preventDefault();
          event.stopPropagation();
          
          showFormWarning(form, formData);
        }
      } catch (error) {
        console.error('Form intercept error:', error);
      }
    }, true);
  }
  
  function analyzeForm(form) {
    try {
      const hasPassword = form.querySelector('input[type="password"]') !== null;
      const hasPin = Array.from(form.querySelectorAll('input')).some(input => {
        const name = (input.name || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        return name.includes('pin') || id.includes('pin') || placeholder.includes('pin');
      });
      
      const hasSSN = Array.from(form.querySelectorAll('input')).some(input => {
        const name = (input.name || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        return name.includes('ssn') || name.includes('social') || 
               id.includes('ssn') || id.includes('social') ||
               placeholder.includes('ssn') || placeholder.includes('social');
      });
      
      const action = form.action || window.location.href;
      const isHidden = form.offsetParent === null;
      
      let suspicious = false;
      const reasons = [];
      let riskScore = 0;
      
      if (hasPassword && !window.location.href.startsWith('https://')) {
        suspicious = true;
        reasons.push('Password form on non-HTTPS page');
        riskScore += 30;
      }
      
      if (action && !action.startsWith('https://')) {
        suspicious = true;
        reasons.push('Form submits over non-secure connection');
        riskScore += 25;
      }
      
      if (isHidden) {
        suspicious = true;
        reasons.push('Hidden form submission');
        riskScore += 30;
      }
      
      try {
        const currentDomain = new URL(window.location.href).hostname;
        const actionDomain = action ? new URL(action).hostname : currentDomain;
        
        if (actionDomain !== currentDomain && (hasPassword || hasPin || hasSSN)) {
          suspicious = true;
          reasons.push(`Form submits to external domain: ${actionDomain}`);
          riskScore += 25;
        }
      } catch (e) {
        // Ignore URL parsing errors
      }
      
      if (hasPassword && hasPin && hasSSN) {
        suspicious = true;
        reasons.push('Contains password, PIN, and SSN fields together');
        riskScore += 40;
      }
      
      return {
        hasPassword,
        hasPin,
        hasSSN,
        action,
        isHidden,
        suspicious,
        reasons,
        riskScore: Math.min(riskScore, 100)
      };
    } catch (error) {
      console.error('Form analysis error:', error);
      return { suspicious: false, riskScore: 0, reasons: [] };
    }
  }
  
  function showFormWarning(form, formData) {
    try {
      const existingWarning = form.parentNode.querySelector('.phishguard-form-warning');
      if (existingWarning) {
        existingWarning.remove();
      }
      
      const warning = document.createElement('div');
      warning.className = 'phishguard-form-warning';
      warning.innerHTML = `
        <div class="phishguard-form-warning-content">
          <h3>⚠️ Suspicious Form Detected</h3>
          <p><strong>This form has characteristics commonly associated with phishing:</strong></p>
          <ul>
            ${formData.reasons.map(r => `<li>${r}</li>`).join('')}
          </ul>
          <p class="phishguard-form-risk">Risk Level: <strong>${formData.riskScore}/100</strong></p>
          <div class="phishguard-form-actions">
            <button id="phishguard-form-cancel" class="phishguard-btn phishguard-btn-primary">
              ✓ Cancel Submission (Recommended)
            </button>
            <button id="phishguard-form-proceed" class="phishguard-btn phishguard-btn-danger">
              ⚠️ Submit Anyway (Not Recommended)
            </button>
          </div>
        </div>
      `;
      
      form.parentNode.insertBefore(warning, form);
      
      document.getElementById('phishguard-form-cancel').addEventListener('click', () => {
        warning.remove();
      });
      
      document.getElementById('phishguard-form-proceed').addEventListener('click', () => {
        warning.remove();
        form.submit();
      });
    } catch (error) {
      console.error('Warning display error:', error);
    }
  }
  
  // ============ DOM OBSERVATION ============
  function observeDOM() {
    try {
      if (!document.body) {
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', observeDOM);
        }
        return;
      }
      
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === 1) {
              const links = node.querySelectorAll ? node.querySelectorAll('a') : [];
              links.forEach(link => {
                if (link.href && !checkedLinks.has(link.href)) {
                  // Will be checked on hover
                }
              });
            }
          });
        });
      });
      
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    } catch (error) {
      console.error('Observer error:', error);
    }
  }
  
  // ============ CLIPBOARD MONITORING (SIMPLIFIED) ============
  function initClipboardMonitoring() {
    let lastCopied = '';
    
    document.addEventListener('copy', () => {
      setTimeout(() => {
        navigator.clipboard.readText().then(text => {
          lastCopied = text;
          console.log('📋 Clipboard: Text copied (PhishGuard monitoring)');
        }).catch(() => {
          // Permission denied or not available
        });
      }, 100);
    });
    
    document.addEventListener('paste', (e) => {
      const pastedText = e.clipboardData.getData('text');
      if (lastCopied && pastedText && lastCopied !== pastedText) {
        console.warn('⚠️ CLIPBOARD HIJACK DETECTED!');
        console.warn('Copied:', lastCopied.substring(0, 50));
        console.warn('Pasted:', pastedText.substring(0, 50));
        
        // Show warning
        alert(
          '⚠️ CLIPBOARD HIJACK DETECTED!\n\n' +
          'The text you copied has been modified!\n\n' +
          'Original: ' + lastCopied.substring(0, 50) + '...\n' +
          'Modified: ' + pastedText.substring(0, 50) + '...\n\n' +
          'This could be a phishing attack!'
        );
      }
    });
  }
  
  // ============ HELPER FUNCTIONS ============
  function showAnalyzingIndicator(element) {
    const indicator = document.createElement('span');
    indicator.className = 'phishguard-analyzing';
    indicator.textContent = '🔍 Analyzing...';
    element.appendChild(indicator);
  }
  
  function hideAnalyzingIndicator() {
    document.querySelectorAll('.phishguard-analyzing').forEach(el => el.remove());
  }
  
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  function getReasonText(result) {
    const reasons = {
      'combined_analysis': 'Multiple security vendors and analysis flagged this site',
      'phishing_indicators': 'Multiple high-risk indicators detected',
      'blacklisted': 'This site is on your blacklist',
      'no_api_key': 'Risk indicators detected'
    };
    return reasons[result.reason] || 'This site exhibits suspicious characteristics';
  }
  
  console.log('✅ PhishGuard content script fully initialized');
})();
