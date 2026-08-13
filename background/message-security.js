// Message security and rate limiting module
export class MessageSecurity {
  constructor() {
    this.rateLimiters = new Map(); // tabId -> RateLimiter
    this.maxRequestsPerMinute = 60;
    this.allowedActions = [
      'analyzeURL',
      'getStats',
      'getHistory',
      'clearHistory',
      'addToWhitelist',
      'removeFromWhitelist',
      'addToBlacklist',
      'removeFromBlacklist',
      'getLists'
    ];
  }

  /**
   * Validate message sender
   */
  validateSender(sender) {
    // Must have tab context
    if (!sender.tab) {
      console.warn('❌ Message rejected: no tab context');
      return { valid: false, reason: 'no_tab_context' };
    }

    // Must have valid URL
    if (!sender.url || sender.url.startsWith('chrome://') || sender.url.startsWith('chrome-extension://')) {
      console.warn('❌ Message rejected: invalid sender URL');
      return { valid: false, reason: 'invalid_sender_url' };
    }

    // Verify it's from our content script
    if (!sender.tab.id || sender.tab.id < 0) {
      console.warn('❌ Message rejected: invalid tab ID');
      return { valid: false, reason: 'invalid_tab_id' };
    }

    return { valid: true };
  }

  /**
   * Validate message action
   */
  validateAction(action) {
    if (!action || typeof action !== 'string') {
      return { valid: false, reason: 'invalid_action_type' };
    }

    if (!this.allowedActions.includes(action)) {
      console.warn(`❌ Action rejected: ${action} not in whitelist`);
      return { valid: false, reason: 'action_not_allowed' };
    }

    return { valid: true };
  }

  /**
   * Check rate limit for a tab
   */
  checkRateLimit(tabId) {
    if (!this.rateLimiters.has(tabId)) {
      this.rateLimiters.set(tabId, new TabRateLimiter(this.maxRequestsPerMinute));
    }

    const limiter = this.rateLimiters.get(tabId);
    const allowed = limiter.allowRequest();

    if (!allowed) {
      console.warn(`⚠️ Rate limit exceeded for tab ${tabId}`);
    }

    return allowed;
  }

  /**
   * Clean up old rate limiters
   */
  cleanup() {
    const now = Date.now();
    for (const [tabId, limiter] of this.rateLimiters.entries()) {
      if (now - limiter.lastActivity > 5 * 60 * 1000) { // 5 minutes inactive
        this.rateLimiters.delete(tabId);
      }
    }
  }

  /**
   * Main security check
   */
  validateMessage(request, sender) {
    // Validate sender
    const senderCheck = this.validateSender(sender);
    if (!senderCheck.valid) {
      return { allowed: false, error: senderCheck.reason };
    }

    // Validate action
    const actionCheck = this.validateAction(request.action);
    if (!actionCheck.valid) {
      return { allowed: false, error: actionCheck.reason };
    }

    // Check rate limit
    const rateLimitOk = this.checkRateLimit(sender.tab.id);
    if (!rateLimitOk) {
      return { allowed: false, error: 'rate_limit_exceeded' };
    }

    return { allowed: true };
  }
}

/**
 * Rate limiter for individual tabs
 */
class TabRateLimiter {
  constructor(maxRequests) {
    this.maxRequests = maxRequests;
    this.requests = [];
    this.lastActivity = Date.now();
  }

  allowRequest() {
    const now = Date.now();
    this.lastActivity = now;

    // Remove requests older than 1 minute
    this.requests = this.requests.filter(time => now - time < 60000);

    if (this.requests.length >= this.maxRequests) {
      return false;
    }

    this.requests.push(now);
    return true;
  }

  getRemainingQuota() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < 60000);
    return Math.max(0, this.maxRequests - this.requests.length);
  }
}
