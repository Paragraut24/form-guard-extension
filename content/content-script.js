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
      
      // Skip if already processed
      if (link.hasAttribute('data-phishguard-checked')) return;
      
      console.log('🔍 Checking link:', url);
      
      const quickCheck = performQuickCheck(url);
      console.log('Quick check result:', quickCheck);
      
      if (quickCheck.suspicious) {
        console.log('⚠️ Suspicious link detected!');
        addVisualWarning(link, 'suspicious', quickCheck);
        link.setAttribute('data-phishguard-checked', 'true');
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
  function addVisualWarning(element, level, checkResult) {
    try {
      console.log('Adding visual warning to element:', element);
      
      // Add warning class
      element.classList.add('phishguard-warning');
      element.classList.add(`phishguard-${level}`);
      
      // Add inline styles as backup (in case CSS doesn't load)
      element.style.border = '2px solid #f59e0b';
      element.style.background = 'rgba(251, 146, 60, 0.15)';
      element.style.padding = '2px 4px';
      element.style.borderRadius = '4px';
      element.style.position = 'relative';
      
      // Create tooltip
      const tooltip = document.createElement('div');
      tooltip.className = 'phishguard-tooltip';
      tooltip.style.cssText = `
        position: absolute;
        bottom: 100%;
        left: 0;
        background: #0f172a;
        color: #fbbf24;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        white-space: nowrap;
        z-index: 999999;
        box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        margin-bottom: 5px;
        pointer-events: none;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        display: none;
      `;
      
      // Tooltip content
      const reasons = checkResult.reasons.join(', ');
      tooltip.innerHTML = `⚠️ Suspicious: ${reasons}`;
      
      element.appendChild(tooltip);
      
      // Show tooltip on hover
      element.addEventListener('mouseenter', () => {
        tooltip.style.display = 'block';
        console.log('Tooltip shown');
      });
      
      element.addEventListener('mouseleave', () => {
        tooltip.style.display = 'none';
      });
      
      console.log('✅ Visual warning added successfully');
      
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
  
  // ============ ENHANCED CLIPBOARD MONITORING ============
  function initClipboardMonitoring() {
    // Check if user consented to clipboard monitoring
    chrome.storage.local.get('clipboard_monitoring_enabled', (data) => {
      if (!data.clipboard_monitoring_enabled) {
        console.log('📋 Clipboard monitoring disabled by user preference');
        return;
      }
      
      console.log('📋 Clipboard monitoring enabled');
      
      let lastCopied = '';
      let lastCopiedTime = 0;
    
    // Monitor copy events
    document.addEventListener('copy', () => {
      setTimeout(() => {
        try {
          // Try clipboard API first
          navigator.clipboard.readText().then(text => {
            lastCopied = text;
            lastCopiedTime = Date.now();
            console.log('📋 Clipboard: Text copied (PhishGuard monitoring)');
          }).catch(() => {
            // Fallback to selection
            const selection = window.getSelection().toString();
            if (selection) {
              lastCopied = selection;
              lastCopiedTime = Date.now();
              console.log('📋 Clipboard: Text copied (PhishGuard monitoring)');
            }
          });
        } catch (error) {
          console.error('Copy monitoring error:', error);
        }
      }, 100);
    });
    
    // Monitor paste events
    document.addEventListener('paste', (e) => {
      // Only check if we have a recent copy (within last 30 seconds)
      if (!lastCopied || Date.now() - lastCopiedTime > 30000) {
        return;
      }
      
      // Check what was actually pasted AFTER paste completes
      setTimeout(() => {
        try {
          const target = e.target;
          let pastedText = '';
          
          // Get pasted content from different element types
          if (target.tagName === 'TEXTAREA' || target.tagName === 'INPUT') {
            pastedText = target.value;
          } else if (target.isContentEditable) {
            pastedText = target.textContent || target.innerText;
          }
          
          // Check for hijacking
          if (pastedText && 
              lastCopied && 
              lastCopied.length > 5 && 
              !pastedText.includes(lastCopied.trim()) &&
              pastedText !== lastCopied) {
            
            console.error('🚨 CLIPBOARD HIJACK DETECTED!');
            console.error('User copied:', lastCopied);
            console.error('Actually pasted:', pastedText);
            
            // Show custom warning modal
            showClipboardHijackAlert(lastCopied, pastedText, target);
          }
        } catch (error) {
          console.error('Paste monitoring error:', error);
        }
      }, 150);
    });
    }); // End of clipboard consent check
  }
  
  function showClipboardHijackAlert(originalText, hijackedText, targetElement) {
    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      z-index: 999998;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    // Create modal
    const modal = document.createElement('div');
    modal.style.cssText = `
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 3px solid #ef4444;
      border-radius: 16px;
      padding: 30px;
      max-width: 600px;
      width: 90%;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.9);
      animation: slideIn 0.3s ease-out;
    `;
    
    modal.innerHTML = `
      <style>
        @keyframes slideIn {
          from { transform: translateY(-50px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
      </style>
      <div style="color: #f87171; font-size: 24px; font-weight: bold; margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 32px;">⚠️</span>
        CLIPBOARD HIJACK DETECTED!
      </div>
      
      <div style="color: #e0e6ed; font-size: 14px; line-height: 1.6; margin-bottom: 20px;">
        This website attempted to change what you pasted! This is a common phishing technique to steal cryptocurrency addresses or sensitive information.
      </div>
      
      <div style="background: #0a0e27; border: 1px solid #22c55e; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
        <div style="color: #94a3b8; font-size: 12px; margin-bottom: 5px; font-weight: 600;">✅ YOU COPIED:</div>
        <div style="color: #4ade80; font-family: 'Courier New', monospace; font-size: 13px; word-break: break-all; max-height: 80px; overflow-y: auto;">
          ${escapeHtml(originalText.substring(0, 200))}${originalText.length > 200 ? '...' : ''}
        </div>
      </div>
      
      <div style="background: #0a0e27; border: 1px solid #ef4444; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
        <div style="color: #94a3b8; font-size: 12px; margin-bottom: 5px; font-weight: 600;">🚨 WEBSITE CHANGED IT TO:</div>
        <div style="color: #f87171; font-family: 'Courier New', monospace; font-size: 13px; word-break: break-all; max-height: 80px; overflow-y: auto;">
          ${escapeHtml(hijackedText.substring(0, 200))}${hijackedText.length > 200 ? '...' : ''}
        </div>
      </div>
      
      <div style="background: rgba(251, 191, 36, 0.1); border-left: 3px solid #fbbf24; padding: 12px; margin-bottom: 20px; border-radius: 4px;">
        <div style="color: #fbbf24; font-size: 13px; line-height: 1.5;">
          <strong>⚠️ Warning:</strong> Never paste cryptocurrency addresses, passwords, or sensitive data on untrusted websites!
        </div>
      </div>
      
      <div style="display: flex; gap: 10px;">
        <button id="phishguard-restore-btn" style="
          flex: 1;
          padding: 12px;
          background: #22c55e;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
        ">
          ✅ Restore Original Text
        </button>
        <button id="phishguard-close-btn" style="
          flex: 1;
          padding: 12px;
          background: #ef4444;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
        ">
          Close Warning
        </button>
      </div>
    `;
    
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    
    // Restore button
    document.getElementById('phishguard-restore-btn').addEventListener('click', () => {
      if (targetElement) {
        if (targetElement.tagName === 'TEXTAREA' || targetElement.tagName === 'INPUT') {
          targetElement.value = originalText;
        } else if (targetElement.isContentEditable) {
          targetElement.textContent = originalText;
        }
      }
      overlay.remove();
    });
    
    // Close button
    document.getElementById('phishguard-close-btn').addEventListener('click', () => {
      overlay.remove();
    });
    
    // Click overlay to close
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.remove();
      }
    });
    
    // Auto-close after 20 seconds
    setTimeout(() => {
      if (overlay.parentElement) {
        overlay.remove();
      }
    }, 20000);
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
