// Machine Learning analyzer for client-side URL analysis
export class MLAnalyzer {
  constructor() {
    this.suspiciousTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', 
      '.top', '.xyz', '.club', '.work', '.click', '.website',
      '.site', '.online', '.space', '.info'
    ];
    
    this.popularDomains = [
      'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
      'apple.com', 'netflix.com', 'paypal.com', 'linkedin.com',
      'twitter.com', 'instagram.com', 'youtube.com', 'github.com',
      'reddit.com', 'wikipedia.org', 'stackoverflow.com'
    ];
    
    this.suspiciousKeywords = [
      'login', 'signin', 'account', 'verify', 'security', 'update',
      'confirm', 'suspend', 'restore', 'unlock', 'secure', 'banking',
      'paypal', 'amazon', 'microsoft', 'apple', 'netflix', 'validation',
      'authentication', 'credential', 'password-reset', 'account-recovery'
    ];
  }
  
  // STRICT trusted domain check - exact matches only
  isTrustedDomain(hostname) {
    const trustedExact = {
      'google.com': true,
      'www.google.com': true,
      'google.co.in': true,
      'www.google.co.in': true,
      'bing.com': true,
      'www.bing.com': true,
      'yahoo.com': true,
      'www.yahoo.com': true,
      'duckduckgo.com': true,
      'www.duckduckgo.com': true,
      'youtube.com': true,
      'www.youtube.com': true,
      'facebook.com': true,
      'www.facebook.com': true,
      'twitter.com': true,
      'www.twitter.com': true,
      'x.com': true,
      'www.x.com': true,
      'instagram.com': true,
      'www.instagram.com': true,
      'linkedin.com': true,
      'www.linkedin.com': true,
      'github.com': true,
      'www.github.com': true,
      'reddit.com': true,
      'www.reddit.com': true,
      'wikipedia.org': true,
      'en.wikipedia.org': true,
      'stackoverflow.com': true,
      'www.stackoverflow.com': true,
      'microsoft.com': true,
      'www.microsoft.com': true,
      'apple.com': true,
      'www.apple.com': true,
      'amazon.com': true,
      'www.amazon.com': true,
      'netflix.com': true,
      'www.netflix.com': true,
      'spotify.com': true,
      'open.spotify.com': true,
      'discord.com': true,
      'www.discord.com': true,
      'cloudflare.com': true,
      'www.cloudflare.com': true
    };
    
    return trustedExact[hostname.toLowerCase()] === true;
  }
  
  async analyze(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      
      // Check trusted domain - EXACT match only
      if (this.isTrustedDomain(hostname)) {
        console.log('✅ Trusted domain (exact match):', hostname);
        return {
          score: 0,
          confidence: 1.0,
          features: {
            isTrustedDomain: true,
            domain: hostname
          }
        };
      }
      
      console.log('🔍 Analyzing potentially risky domain:', hostname);
      
      const features = this.extractFeatures(url);
      const score = this.calculateRiskScore(features);
      const confidence = this.calculateConfidence(features);
      
      console.log('📊 ML Score:', score, 'Confidence:', confidence);
      
      return {
        score,
        confidence,
        features
      };
    } catch (error) {
      console.error('❌ ML analysis error:', error);
      return {
        score: 50,
        confidence: 0.3,
        features: { error: error.message }
      };
    }
  }
  
  extractFeatures(url) {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;
    const fullURL = url;
    
    const encodedCharCount = (fullURL.match(/%[0-9A-Fa-f]{2}/g) || []).length;
    
    // Check for suspicious keywords in URL
    const urlLower = fullURL.toLowerCase();
    const suspiciousKeywordCount = this.suspiciousKeywords.filter(kw => 
      urlLower.includes(kw)
    ).length;
    
    return {
      urlLength: fullURL.length,
      domainLength: domain.length,
      pathLength: path.length,
      
      numDots: (fullURL.match(/\./g) || []).length,
      numHyphens: (domain.match(/-/g) || []).length,
      numDigits: (domain.match(/\d/g) || []).length,
      numSpecialChars: (fullURL.match(/[^a-zA-Z0-9.-]/g) || []).length,
      
      hasHTTPS: urlObj.protocol === 'https:',
      hasIPAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain),
      
      hasSuspiciousTLD: this.suspiciousTLDs.some(tld => domain.endsWith(tld)),
      hasAtSymbol: fullURL.includes('@'),
      hasDoubleSlash: path.includes('//'),
      
      suspiciousKeywordCount: suspiciousKeywordCount,
      typosquattingScore: this.detectTyposquatting(domain),
      
      encodedCharCount: encodedCharCount,
      hasEncodedChars: encodedCharCount > 0,
      hasUnicodeChars: /[^\x00-\x7F]/.test(fullURL),
      
      numSubdomains: domain.split('.').length - 2,
      hasLongSubdomain: domain.split('.').some(part => part.length > 20),
      
      // New: Check for free hosting services (high phishing risk)
      isFreeHosting: this.detectFreeHosting(domain)
    };
  }
  
  detectFreeHosting(domain) {
    const freeHostingServices = [
      'weebly.com', 'wixsite.com', 'wordpress.com', 'blogspot.com',
      'tumblr.com', 'square.site', 'webflow.io', '000webhostapp.com',
      'tk', 'ml', 'ga', 'cf', 'gq'
    ];
    
    return freeHostingServices.some(service => {
      // Check if domain ends with the service (e.g., xxx.weebly.com)
      if (domain.endsWith('.' + service)) return true;
      // Check if domain is exactly the service
      if (domain === service) return true;
      return false;
    });
  }
  
  calculateRiskScore(features) {
    let score = 0;
    
    // Free hosting = HIGH RISK (phishing commonly uses these)
    if (features.isFreeHosting) score += 35;
    
    // Length penalties - more strict
    if (features.urlLength > 150) score += 10;
    if (features.urlLength > 250) score += 10;
    if (features.domainLength > 40) score += 15;
    
    // Character anomalies
    if (features.numDots > 5) score += 10;
    if (features.numHyphens > 3) score += 10;
    if (features.numDigits > 4) score += 10;
    if (features.numSpecialChars > 20) score += 10;
    if (features.numSpecialChars > 40) score += 15;
    
    // Security issues - CRITICAL
    if (!features.hasHTTPS) score += 25;
    if (features.hasIPAddress) score += 30;
    
    // Suspicious patterns - HIGH RISK
    if (features.hasSuspiciousTLD) score += 35;
    if (features.hasAtSymbol) score += 25;
    if (features.hasDoubleSlash) score += 20;
    
    // Suspicious keywords (login, verify, etc.)
    if (features.suspiciousKeywordCount > 0) {
      score += features.suspiciousKeywordCount * 8;
    }
    
    // Typosquatting
    score += features.typosquattingScore;
    
    // Obfuscation
    if (features.encodedCharCount > 10) score += 15;
    else if (features.encodedCharCount > 5) score += 5;
    if (features.hasUnicodeChars) score += 15;
    
    // Subdomain issues
    if (features.numSubdomains > 3) score += 15;
    if (features.hasLongSubdomain) score += 15;
    
    return Math.min(score, 100);
  }
  
  detectTyposquatting(domain) {
    let maxSimilarity = 0;
    
    for (const popular of this.popularDomains) {
      const similarity = this.calculateSimilarity(domain, popular);
      if (similarity > maxSimilarity) {
        maxSimilarity = similarity;
      }
    }
    
    // High similarity but not exact = likely typosquatting
    if (maxSimilarity > 0.85 && maxSimilarity < 1.0) {
      return 45;
    } else if (maxSimilarity > 0.75) {
      return 25;
    }
    
    return 0;
  }
  
  calculateSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    
    if (longer.length === 0) return 1.0;
    
    const editDistance = this.levenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }
  
  levenshteinDistance(str1, str2) {
    const matrix = [];
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    
    return matrix[str2.length][str1.length];
  }
  
  calculateConfidence(features) {
    let confidence = 0.5;
    
    if (features.hasIPAddress) confidence += 0.2;
    if (features.hasSuspiciousTLD) confidence += 0.2;
    if (features.typosquattingScore > 30) confidence += 0.15;
    if (!features.hasHTTPS) confidence += 0.1;
    if (features.isFreeHosting) confidence += 0.15;
    if (features.suspiciousKeywordCount > 2) confidence += 0.1;
    
    return Math.min(confidence, 0.95);
  }
}
