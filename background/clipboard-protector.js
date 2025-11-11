export class ClipboardProtector {
  constructor() {
    this.clipboardHistory = [];
    this.maxHistory = 50;
  }
  
  // Start monitoring clipboard
  startMonitoring() {
    console.log('📋 Clipboard protection enabled');
    
    // Monitor copy events
    document.addEventListener('copy', (e) => {
      const copiedText = window.getSelection().toString();
      this.logClipboardAction('copy', copiedText);
    });
    
    // Monitor paste events - THIS IS THE KEY
    document.addEventListener('paste', (e) => {
      const pastedText = e.clipboardData.getData('text/plain');
      this.logClipboardAction('paste', pastedText);
      
      // Check if pasted text differs from what was copied
      this.validatePasteContent(pastedText);
    });
  }
  
  logClipboardAction(type, content) {
    this.clipboardHistory.unshift({
      type,
      content: content.substring(0, 100), // Store first 100 chars
      timestamp: Date.now(),
      hash: this.hashContent(content)
    });
    
    // Keep only last 50 actions
    if (this.clipboardHistory.length > this.maxHistory) {
      this.clipboardHistory.pop();
    }
  }
  
  validatePasteContent(pastedContent) {
    const recentCopy = this.clipboardHistory.find(h => h.type === 'copy');
    
    if (!recentCopy) {
      console.log('⚠️ Pasted content with no recent copy');
      return;
    }
    
    const copiedHash = recentCopy.hash;
    const pastedHash = this.hashContent(pastedContent);
    
    // If hashes don't match, clipboard was hijacked
    if (copiedHash !== pastedHash) {
      console.warn('🚨 CLIPBOARD HIJACK DETECTED!');
      this.alertClipboardHijack(recentCopy.content, pastedContent);
      return false;
    }
    
    console.log('✅ Clipboard content verified');
    return true;
  }
  
  alertClipboardHijack(original, modified) {
    chrome.runtime.sendMessage({
      action: 'clipboardHijackDetected',
      original: original.substring(0, 50) + '...',
      modified: modified.substring(0, 50) + '...'
    }).catch(() => {});
  }
  
  hashContent(content) {
    // Simple hash function
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }
  
  getClipboardHistory() {
    return this.clipboardHistory;
  }
}
