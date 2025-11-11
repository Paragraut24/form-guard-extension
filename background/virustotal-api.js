    // VirusTotal API integration
export class VirusTotalAPI {
  constructor() {
    this.baseURL = 'https://www.virustotal.com/api/v3';
  }
  
  async scanURL(url, apiKey, privacyMode = false) {
    // Hash URL if privacy mode is enabled
    const urlToScan = privacyMode ? await this.hashURL(url) : url;
    
    // First, check if URL has been scanned before
    const urlId = btoa(url).replace(/=/g, '');
    
    try {
      // Try to get existing analysis
      const response = await fetch(`${this.baseURL}/urls/${urlId}`, {
        headers: {
          'x-apikey': apiKey
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        return this.parseVTResponse(data);
      }
      
      // If not found, submit for scanning
      const scanResponse = await this.submitURL(url, apiKey);
      
      // Wait a bit and retry getting results
      await this.delay(5000);
      const analysisResponse = await fetch(`${this.baseURL}/analyses/${scanResponse.id}`, {
        headers: {
          'x-apikey': apiKey
        }
      });
      
      if (analysisResponse.ok) {
        const data = await analysisResponse.json();
        return this.parseVTResponse(data);
      }
      
      // Return pending if analysis not ready
      return {
        status: 'pending',
        score: 50,
        detections: 0,
        totalEngines: 0
      };
      
    } catch (error) {
      throw new Error(`VirusTotal API error: ${error.message}`);
    }
  }
  
  async submitURL(url, apiKey) {
    const formData = new FormData();
    formData.append('url', url);
    
    const response = await fetch(`${this.baseURL}/urls`, {
      method: 'POST',
      headers: {
        'x-apikey': apiKey
      },
      body: formData
    });
    
    if (!response.ok) {
      throw new Error(`Failed to submit URL: ${response.status}`);
    }
    
    const data = await response.json();
    return data.data;
  }
  
  parseVTResponse(data) {
    const stats = data.data.attributes.last_analysis_stats || data.data.attributes.stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    
    const detections = malicious + suspicious;
    const score = total > 0 ? Math.round((detections / total) * 100) : 0;
    
    let status = 'safe';
    if (malicious > 5) status = 'malicious';
    else if (malicious > 0 || suspicious > 3) status = 'suspicious';
    
    return {
      status,
      score,
      detections,
      totalEngines: total,
      malicious,
      suspicious
    };
  }
  
  async hashURL(url) {
    const encoder = new TextEncoder();
    const data = encoder.encode(url);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
