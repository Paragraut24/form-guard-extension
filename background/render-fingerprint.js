export class RenderFingerprint {
  // Get unique fingerprint of page rendering
  async captureFingerprint(tabId) {
    return new Promise((resolve) => {
      chrome.tabs.executeScript(tabId, {
        code: `
          (function() {
            const fingerprint = {
              fonts: [],
              colors: [],
              fontSizes: [],
              computedStyles: {}
            };
            
            // Extract fonts
            document.querySelectorAll('*').forEach(el => {
              const style = window.getComputedStyle(el);
              const font = style.fontFamily;
              const fontSize = style.fontSize;
              const color = style.color;
              
              if (font) fingerprint.fonts.push(font);
              if (color) fingerprint.colors.push(color);
              if (fontSize) fingerprint.fontSizes.push(fontSize);
            });
            
            // Get CSS rules
            try {
              for (let sheet of document.styleSheets) {
                const rules = sheet.cssRules || sheet.rules;
                for (let rule of rules) {
                  if (rule.style) {
                    fingerprint.computedStyles[rule.selectorText] = rule.style.cssText;
                  }
                }
              }
            } catch (e) {
              // Cross-origin sheets
            }
            
            // Create hash of fingerprint
            const hash = btoa(JSON.stringify(fingerprint));
            window.phishguardFingerprint = { fingerprint, hash };
          })();
          window.phishguardFingerprint
        `
      }, (results) => {
        if (results && results[0]) {
          resolve(results[0]);
        } else {
          resolve({ fingerprint: {}, hash: null });
        }
      });
    });
  }
  
  // Compare with known legitimate sites
  async compareFingersints(currentHash, knownFingerprints) {
    let similarityScore = 0;
    
    for (const known of knownFingerprints) {
      // Simple string similarity
      if (currentHash === known.hash) {
        similarityScore = 100; // Perfect match
        break;
      }
      
      // Partial match
      const commonChars = currentHash.split('').filter(c => known.hash.includes(c)).length;
      const score = (commonChars / Math.max(currentHash.length, known.hash.length)) * 100;
      
      if (score > similarityScore) {
        similarityScore = score;
      }
    }
    
    console.log('🎨 Render similarity:', similarityScore + '%');
    
    // If 70-95% similar but not 100%, likely a clone
    if (similarityScore > 70 && similarityScore < 95) {
      return {
        isClone: true,
        confidence: 'high',
        riskScore: 60
      };
    }
    
    return {
      isClone: false,
      confidence: 'low',
      riskScore: 0
    };
  }
}
