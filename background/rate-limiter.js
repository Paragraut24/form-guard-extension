// Rate limiter for VirusTotal API calls
export class RateLimiter {
  constructor(maxRequests, timeWindow) {
    this.maxRequests = maxRequests;
    this.timeWindow = timeWindow;
    this.requests = [];
  }
  
  canMakeRequest() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.timeWindow);
    return this.requests.length < this.maxRequests;
  }
  
  recordRequest() {
    this.requests.push(Date.now());
  }
  
  getWaitTime() {
    if (this.requests.length === 0) return 0;
    const oldestRequest = Math.min(...this.requests);
    const timeToWait = this.timeWindow - (Date.now() - oldestRequest);
    return Math.max(timeToWait, 0);
  }
}
