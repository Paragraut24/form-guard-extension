// preview.js - Safe preview with interaction blocking

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('url');

console.log('=== SAFE PREVIEW LOADED ===');
console.log('Target URL:', targetUrl);

document.addEventListener('DOMContentLoaded', () => {
  if (!targetUrl) {
    alert('⚠️ No URL provided for preview');
    window.close();
    return;
  }
  
  // Display URL
  document.getElementById('urlDisplay').textContent = targetUrl;
  
  // Load iframe with full permissions (but we'll block interactions)
  const iframe = document.getElementById('previewFrame');
  
  // Remove sandbox to allow loading
  iframe.removeAttribute('sandbox');
  iframe.src = targetUrl;
  
  // Hide loading after iframe loads
  iframe.addEventListener('load', () => {
    console.log('✓ Preview loaded');
    setTimeout(() => {
      const loading = document.getElementById('loading');
      if (loading) {
        loading.style.display = 'none';
      }
    }, 1000);
  });
  
  // Handle load errors
  iframe.addEventListener('error', () => {
    console.error('Failed to load preview');
    const loading = document.getElementById('loading');
    if (loading) {
      loading.innerHTML = `
        <div style="color: #f87171;">
          <p style="font-size: 18px; margin-bottom: 10px;">❌ Failed to Load</p>
          <p style="font-size: 14px;">The site could not be previewed.</p>
          <p style="font-size: 12px; margin-top: 10px; opacity: 0.7;">
            This may happen if the site blocks embedding.
          </p>
        </div>
      `;
    }
  });
  
  // Setup close button
  document.getElementById('closeBtn').addEventListener('click', () => {
    console.log('Closing preview');
    window.close();
  });
  
  // Block all keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    // Allow only Ctrl+W to close
    if (e.ctrlKey && e.key === 'w') {
      return true;
    }
    // Block everything else
    if (e.target.tagName !== 'BUTTON') {
      e.preventDefault();
      e.stopPropagation();
      console.log('Blocked keyboard interaction');
      return false;
    }
  }, true);
  
  // Block context menu
  document.addEventListener('contextmenu', (e) => {
    if (e.target.tagName !== 'BUTTON') {
      e.preventDefault();
      return false;
    }
  });
  
  // Show warning on any attempted interaction
  let warningTimeout;
  document.querySelector('.interaction-blocker').addEventListener('click', () => {
    const warning = document.querySelector('.warning-overlay');
    warning.style.background = 'rgba(239, 68, 68, 1)';
    warning.style.transform = 'scale(1.1)';
    
    clearTimeout(warningTimeout);
    warningTimeout = setTimeout(() => {
      warning.style.background = 'rgba(239, 68, 68, 0.95)';
      warning.style.transform = 'scale(1)';
    }, 500);
  });
});

// Prevent navigation
window.addEventListener('beforeunload', (e) => {
  if (e.target.activeElement.id !== 'closeBtn') {
    e.preventDefault();
    return '';
  }
});

console.log('✓ Safe preview initialized');
