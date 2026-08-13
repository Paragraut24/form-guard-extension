// Secure storage module for sensitive data encryption
export class SecureStorage {
  constructor() {
    this.algorithm = 'AES-GCM';
    this.keyLength = 256;
    this.saltKey = 'phishguard_salt_v1';
    this.masterKeyCache = null;
  }

  /**
   * Generate a master key from browser's crypto API
   * Uses a combination of extension ID and timestamp for uniqueness
   */
  async getMasterKey() {
    if (this.masterKeyCache) {
      return this.masterKeyCache;
    }

    // Get or create salt
    let salt = await this.getSalt();
    if (!salt) {
      salt = crypto.getRandomValues(new Uint8Array(16));
      await this.storeSalt(salt);
    }

    // Derive key material from extension context
    const extensionId = chrome.runtime.id;
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(extensionId + '_phishguard_key'),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    // Derive AES key
    const masterKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: this.algorithm, length: this.keyLength },
      false,
      ['encrypt', 'decrypt']
    );

    this.masterKeyCache = masterKey;
    return masterKey;
  }

  async getSalt() {
    const data = await chrome.storage.local.get(this.saltKey);
    return data[this.saltKey] ? new Uint8Array(data[this.saltKey]) : null;
  }

  async storeSalt(salt) {
    await chrome.storage.local.set({ [this.saltKey]: Array.from(salt) });
  }

  /**
   * Encrypt sensitive data
   */
  async encrypt(plaintext) {
    if (!plaintext) return null;

    const masterKey = await this.getMasterKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const encrypted = await crypto.subtle.encrypt(
      { name: this.algorithm, iv },
      masterKey,
      data
    );

    return {
      encrypted: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv),
      timestamp: Date.now()
    };
  }

  /**
   * Decrypt sensitive data
   */
  async decrypt(encryptedData) {
    if (!encryptedData || !encryptedData.encrypted || !encryptedData.iv) {
      return null;
    }

    try {
      const masterKey = await this.getMasterKey();
      const encrypted = new Uint8Array(encryptedData.encrypted);
      const iv = new Uint8Array(encryptedData.iv);

      const decrypted = await crypto.subtle.decrypt(
        { name: this.algorithm, iv },
        masterKey,
        encrypted
      );

      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      console.error('Decryption failed:', error);
      return null;
    }
  }

  /**
   * Store API key securely
   */
  async storeApiKey(apiKey) {
    if (!apiKey) {
      throw new Error('API key cannot be empty');
    }

    const encrypted = await this.encrypt(apiKey);
    await chrome.storage.local.set({ 
      encrypted_api_key: encrypted,
      api_key_rotation_date: Date.now()
    });
    
    console.log('✅ API key stored securely');
  }

  /**
   * Retrieve API key securely
   */
  async getApiKey() {
    const data = await chrome.storage.local.get('encrypted_api_key');
    if (!data.encrypted_api_key) {
      return null;
    }

    const decrypted = await this.decrypt(data.encrypted_api_key);
    return decrypted;
  }

  /**
   * Check if API key needs rotation (90 days)
   */
  async needsKeyRotation() {
    const data = await chrome.storage.local.get('api_key_rotation_date');
    if (!data.api_key_rotation_date) {
      return false;
    }

    const daysSinceRotation = (Date.now() - data.api_key_rotation_date) / (1000 * 60 * 60 * 24);
    return daysSinceRotation > 90;
  }

  /**
   * Validate API key format (basic check)
   */
  validateApiKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
      return false;
    }

    // VirusTotal API keys are 64 character hex strings
    const vtKeyPattern = /^[a-f0-9]{64}$/i;
    return vtKeyPattern.test(apiKey);
  }

  /**
   * Clear all secure data
   */
  async clearSecureData() {
    await chrome.storage.local.remove(['encrypted_api_key', 'api_key_rotation_date', this.saltKey]);
    this.masterKeyCache = null;
    console.log('✅ Secure data cleared');
  }
}
