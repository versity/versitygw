// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

/**
 * VersityGW Admin API Client
 * Implements AWS Signature V4 signing for admin and S3 API requests
 * Supports dual-mode: Admin (full UI) and S3-only (Explorer only)
 */

/**
 * CryptoJS wrapper for SHA-256 and HMAC-SHA256 operations
 * Used as fallback when crypto.subtle is unavailable (non-HTTPS contexts)
 * Requires: CryptoJS library (loaded via script tag in HTML)
 */
const CryptoJSWrapper = {
  // SHA-256 returning hex string
  sha256(message) {
    if (typeof CryptoJS === 'undefined') {
      throw new Error('CryptoJS library not loaded');
    }
    return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
  },

  // SHA-256 returning Uint8Array
  sha256Bytes(message) {
    if (typeof CryptoJS === 'undefined') {
      throw new Error('CryptoJS library not loaded');
    }
    const wordArray = CryptoJS.SHA256(message);
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const bytes = new Uint8Array(sigBytes);
    
    for (let i = 0; i < sigBytes; i++) {
      bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return bytes;
  },

  // HMAC-SHA256 returning Uint8Array
  hmacSha256(key, message) {
    if (typeof CryptoJS === 'undefined') {
      throw new Error('CryptoJS library not loaded');
    }
    
    // Convert key to CryptoJS format
    let cryptoKey;
    if (typeof key === 'string') {
      cryptoKey = CryptoJS.enc.Utf8.parse(key);
    } else if (key instanceof Uint8Array) {
      // Convert Uint8Array to WordArray
      const words = [];
      for (let i = 0; i < key.length; i += 4) {
        const word = (key[i] << 24) | (key[i + 1] << 16) | (key[i + 2] << 8) | key[i + 3];
        words.push(word);
      }
      cryptoKey = CryptoJS.lib.WordArray.create(words, key.length);
    } else {
      cryptoKey = key;
    }

    // Convert message to CryptoJS format
    let cryptoMessage;
    if (typeof message === 'string') {
      cryptoMessage = CryptoJS.enc.Utf8.parse(message);
    } else if (message instanceof Uint8Array) {
      const words = [];
      for (let i = 0; i < message.length; i += 4) {
        const word = (message[i] << 24) | (message[i + 1] << 16) | (message[i + 2] << 8) | message[i + 3];
        words.push(word);
      }
      cryptoMessage = CryptoJS.lib.WordArray.create(words, message.length);
    } else {
      cryptoMessage = message;
    }

    // Compute HMAC
    const hmac = CryptoJS.HmacSHA256(cryptoMessage, cryptoKey);
    const words = hmac.words;
    const sigBytes = hmac.sigBytes;
    const bytes = new Uint8Array(sigBytes);
    
    for (let i = 0; i < sigBytes; i++) {
      bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return bytes;
  }
};

// Check if crypto.subtle is available (secure context)
const hasSubtleCrypto = typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

/**
 * Encode an S3 object key for use in a URL path.
 * Encodes each path segment but preserves slashes as path separators.
 * @param {string} key - The S3 object key
 * @returns {string} - URL-encoded path
 */
function encodeS3Key(key) {
  if (!key) return '';
  return key.split('/').map(segment => awsUriEncode(segment)).join('/');
}

class VersityAPI {
  constructor() {
    this.credentials = null;
    this.adminEndpoint = null;  // Admin API endpoint (may be null for S3-only users)
    this.s3Endpoint = null;     // S3 API endpoint (always required)
    this.region = 'us-east-1';
    this.addressingStyle = 'path'; // 'path' or 'virtual-host'
    this.iamEndpoint = null;    // Standalone IAM service endpoint (optional)
    this._isAdmin = false;      // Role flag
    this._hasIAM = false;       // Credentials validate against the IAM service
    this._hasS3 = false;        // Credentials validate against the S3 data plane
    this._canListBuckets = false; // hasS3 is true and s3:ListAllMyBuckets is allowed
  }

  /**
   * Create a SigV4 presigned URL (query-string auth) for S3 requests.
   * This avoids sending non-simple headers (Authorization, X-Amz-Date, etc.)
   * and therefore avoids browser CORS preflight in many deployments.
   *
   * Currently used to ensure ListBuckets (GET /) works when the gateway
   * does not implement OPTIONS /.
   */
  async presignUrl(method, path, queryParams = {}, expiresSeconds = 60, useAdminEndpoint = false) {
    if (!this.credentials) {
      throw new Error('Not authenticated');
    }

    const endpoint = this.getEndpoint(useAdminEndpoint);
    const url = new URL(endpoint + path);
    const host = url.host;
    const service = 's3';
    const amzDate = this.getAmzDate();
    const dateStamp = this.getDateStamp();

    // Base query params
    Object.entries(queryParams || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    });

    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${this.region}/${service}/aws4_request`;

    url.searchParams.set('X-Amz-Algorithm', algorithm);
    url.searchParams.set('X-Amz-Credential', `${this.credentials.accessKey}/${credentialScope}`);
    url.searchParams.set('X-Amz-Date', amzDate);
    url.searchParams.set('X-Amz-Expires', String(expiresSeconds));
    url.searchParams.set('X-Amz-SignedHeaders', 'host');

    // Sort query params for canonical request
    const sortedParams = [...url.searchParams.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    const canonicalQueryString = sortedParams
      .map(([k, v]) => `${awsUriEncode(k)}=${awsUriEncode(v)}`)
      .join('&');

    const canonicalHeaders = `host:${host}\n`;
    const signedHeaders = 'host';
    const payloadHash = 'UNSIGNED-PAYLOAD';

    const canonicalRequest = [
      method,
      url.pathname,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash,
    ].join('\n');

    const canonicalRequestHash = await this.sha256(canonicalRequest);
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      canonicalRequestHash,
    ].join('\n');

    const signingKey = await this.getSigningKey(this.credentials.secretKey, dateStamp, this.region, service);
    const signatureBuffer = await this.hmacSha256(signingKey, stringToSign);
    const signature = this.bufferToHex(signatureBuffer);

    url.searchParams.set('X-Amz-Signature', signature);
    return url.toString();
  }

  /**
   * Set credentials for API requests (initial login - assumes same endpoint).
   * An empty endpoint is valid: an IAM-only sign-in has no S3 gateway behind
   * it, and gets its only endpoint from setIAMEndpoint().
   */
  setCredentials(endpoint, accessKey, secretKey, region = 'us-east-1') {
    endpoint = (endpoint || '').trim().replace(/\/$/, '') || null;
    this.adminEndpoint = endpoint;
    this.s3Endpoint = endpoint;
    this.credentials = { accessKey, secretKey };
    this.region = region;
    this._isAdmin = false; // Will be set by detectRole()

    // Store in sessionStorage for persistence across page loads
    this._storeEndpoint('vgw_admin_endpoint', this.adminEndpoint);
    this._storeEndpoint('vgw_s3_endpoint', this.s3Endpoint);
    sessionStorage.setItem('vgw_access_key', accessKey);
    sessionStorage.setItem('vgw_secret_key', secretKey);
    sessionStorage.setItem('vgw_region', region);
    sessionStorage.setItem('vgw_is_admin', 'false');
  }

  /**
   * Set the S3 endpoint separately (when different from admin)
   */
  setS3Endpoint(s3Endpoint) {
    this.s3Endpoint = (s3Endpoint || '').trim().replace(/\/$/, '') || null;
    this._storeEndpoint('vgw_s3_endpoint', this.s3Endpoint);
  }

  /**
   * Persist an endpoint, or clear the key when there isn't one, so that
   * "is this endpoint configured?" is a plain presence check.
   */
  _storeEndpoint(key, value) {
    if (value) {
      sessionStorage.setItem(key, value);
    } else {
      sessionStorage.removeItem(key);
    }
  }

  /**
   * Set the standalone IAM service endpoint (versitygw iam). Optional:
   * without one the IAM navigation and pages stay hidden for the session.
   */
  setIAMEndpoint(iamEndpoint) {
    const normalized = (iamEndpoint || '').trim().replace(/\/$/, '');
    this.iamEndpoint = normalized || null;
    if (this.iamEndpoint) {
      sessionStorage.setItem('vgw_iam_endpoint', this.iamEndpoint);
    } else {
      sessionStorage.removeItem('vgw_iam_endpoint');
    }
  }

  /**
   * Set bucket addressing style ('path' or 'virtual-host')
   */
  setAddressingStyle(style) {
    this.addressingStyle = style || 'path';
    sessionStorage.setItem('vgw_addressing_style', this.addressingStyle);
  }

  /**
   * Set admin role flag
   */
  setAdminRole(isAdmin) {
    this._isAdmin = isAdmin;
    sessionStorage.setItem('vgw_is_admin', isAdmin ? 'true' : 'false');
  }

  /**
   * Set IAM service access flag (independent of the admin flag)
   */
  setHasIAM(hasIAM) {
    this._hasIAM = !!hasIAM;
    sessionStorage.setItem('vgw_has_iam', this._hasIAM ? 'true' : 'false');
  }

  /**
   * Set S3 data-plane access flag (used to route IAM-only sessions)
   */
  setHasS3(hasS3) {
    this._hasS3 = !!hasS3;
    sessionStorage.setItem('vgw_has_s3', this._hasS3 ? 'true' : 'false');
  }

  /**
   * Set whether the session may enumerate all buckets (s3:ListAllMyBuckets),
   * which is separate from having valid S3 credentials: a policy can grant
   * named buckets without the account-wide listing.
   */
  setCanListBuckets(canListBuckets) {
    this._canListBuckets = !!canListBuckets;
    sessionStorage.setItem('vgw_can_list_buckets', this._canListBuckets ? 'true' : 'false');
  }

  /**
   * Load credentials from sessionStorage
   */
  loadCredentials() {
    const adminEndpoint = sessionStorage.getItem('vgw_admin_endpoint');
    const s3Endpoint = sessionStorage.getItem('vgw_s3_endpoint');
    const accessKey = sessionStorage.getItem('vgw_access_key');
    const secretKey = sessionStorage.getItem('vgw_secret_key');
    const region = sessionStorage.getItem('vgw_region') || 'us-east-1';
    const addressingStyle = sessionStorage.getItem('vgw_addressing_style') || 'path';
    const isAdmin = sessionStorage.getItem('vgw_is_admin') === 'true';
    const iamEndpoint = sessionStorage.getItem('vgw_iam_endpoint');
    const hasIAM = sessionStorage.getItem('vgw_has_iam') === 'true';
    const hasS3 = sessionStorage.getItem('vgw_has_s3') === 'true';
    const canListBuckets = sessionStorage.getItem('vgw_can_list_buckets') === 'true';

    // Support legacy single endpoint storage
    const legacyEndpoint = sessionStorage.getItem('vgw_endpoint');

    if ((s3Endpoint || legacyEndpoint || iamEndpoint) && accessKey && secretKey) {
      this.adminEndpoint = adminEndpoint || legacyEndpoint || null;
      this.s3Endpoint = s3Endpoint || legacyEndpoint || null;
      this.credentials = { accessKey, secretKey };
      this.region = region;
      this.addressingStyle = addressingStyle;
      this._isAdmin = isAdmin;
      this.iamEndpoint = iamEndpoint || null;
      this._hasIAM = hasIAM;
      this._hasS3 = hasS3;
      this._canListBuckets = canListBuckets;
      return true;
    }
    return false;
  }

  /**
   * Clear credentials and logout
   */
  logout() {
    this.credentials = null;
    this.adminEndpoint = null;
    this.s3Endpoint = null;
    this.addressingStyle = 'path';
    this.iamEndpoint = null;
    this._isAdmin = false;
    this._hasIAM = false;
    this._hasS3 = false;
    this._canListBuckets = false;
    this._userType = 'user';
    this._accessibleGateways = [];
    sessionStorage.removeItem('vgw_admin_endpoint');
    sessionStorage.removeItem('vgw_s3_endpoint');
    sessionStorage.removeItem('vgw_endpoint'); // Legacy
    sessionStorage.removeItem('vgw_access_key');
    sessionStorage.removeItem('vgw_secret_key');
    sessionStorage.removeItem('vgw_region');
    sessionStorage.removeItem('vgw_addressing_style');
    sessionStorage.removeItem('vgw_is_admin');
    sessionStorage.removeItem('vgw_iam_endpoint');
    sessionStorage.removeItem('vgw_has_iam');
    sessionStorage.removeItem('vgw_has_s3');
    sessionStorage.removeItem('vgw_can_list_buckets');
    sessionStorage.removeItem('vgw_iam_probe_error');
    sessionStorage.removeItem('vgw_user_type');
    sessionStorage.removeItem('vgw_accessible_gateways');
  }

  // ============================================
  // User Context Methods (ROOT user detection)
  // ============================================

  /**
   * Store user type and accessible gateways in session
   * @param {string} userType - 'root' | 'admin' | 'user'
   * @param {Array} accessibleGateways - List of gateways this user can access
   */
  setUserContext(userType, accessibleGateways) {
    this._userType = userType;
    sessionStorage.setItem('vgw_user_type', userType);
  }

  /**
   * Load user context from session storage
   * Called after loadCredentials() to restore user type and gateways
   */
  loadUserContext() {
    this._userType = sessionStorage.getItem('vgw_user_type') || 'user';
  }

  /**
   * Check if user has admin privileges
   */
  isAdmin() {
    return this._isAdmin;
  }

  /**
   * Check whether the session's credentials reach the standalone IAM service
   */
  hasIAM() {
    return this._hasIAM;
  }

  /**
   * Check whether the session's credentials reach the S3 data plane
   */
  hasS3() {
    return this._hasS3;
  }

  /**
   * Check whether the session belongs on the management pages (Dashboard,
   * Buckets): a classic admin session, or any S3 session in a standalone-IAM
   * deployment, where those pages run on the S3 and IAM APIs alone and each
   * denial is surfaced in place rather than hiding the page.
   */
  hasManagement() {
    return this._isAdmin || (this._hasS3 && this._hasIAM);
  }

  /**
   * Check whether the session may enumerate all buckets
   * (s3:ListAllMyBuckets). hasS3() can be true while this is false.
   */
  canListBuckets() {
    return this._canListBuckets;
  }

  /**
   * Get current credentials info (without secret)
   */
  getCredentialsInfo() {
    if (!this.credentials) return null;
    return {
      adminEndpoint: this.adminEndpoint,
      s3Endpoint: this.s3Endpoint,
      endpoint: this.s3Endpoint, // Legacy compatibility
      accessKey: this.credentials.accessKey,
      region: this.region,
      isAdmin: this._isAdmin,
      iamEndpoint: this.iamEndpoint,
      hasIAM: this._hasIAM
    };
  }

  /**
   * Get the appropriate endpoint for a request type
   */
  getEndpoint(useAdmin = false) {
    if (useAdmin && this.adminEndpoint) {
      return this.adminEndpoint;
    }
    return this.s3Endpoint;
  }

  /**
   * Build URL for S3 requests with appropriate addressing style
   * @param {string} path - Request path (e.g., '/bucket/key')
   * @param {boolean} useAdmin - Whether to use admin endpoint
   * @returns {string} - Full URL with endpoint and path
   */
  buildRequestUrl(path, useAdmin = false) {
    const endpoint = this.getEndpoint(useAdmin);
    
    // Admin API and non-S3 requests always use path style
    if (useAdmin) {
      return endpoint + path;
    }

    // For S3 API requests, check addressing style
    if (this.addressingStyle === 'virtual-host') {
      // Extract bucket name from path (format: /bucket/key or /bucket)
      const pathMatch = path.match(/^\/([^\/]+)(\/.*)?$/);
      if (pathMatch) {
        const bucketName = pathMatch[1];
        const keyPath = pathMatch[2] || '/';
        
        // Parse the endpoint URL
        const endpointUrl = new URL(endpoint);
        
        // Create virtual host URL: bucket.host/key
        const virtualHost = `${bucketName}.${endpointUrl.host}`;
        return `${endpointUrl.protocol}//${virtualHost}${keyPath}`;
      }
    }
    
    // Default to path style
    return endpoint + path;
  }

  // ============================================
  // AWS Signature V4 Implementation
  // ============================================

  /**
   * Convert ArrayBuffer to hex string
   */
  bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * SHA-256 hash (uses crypto.subtle in HTTPS, CryptoJS in HTTP)
   */
  async sha256(message) {
    if (hasSubtleCrypto) {
      const encoder = new TextEncoder();
      const data = encoder.encode(message);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      return this.bufferToHex(hashBuffer);
    } else {
      return CryptoJSWrapper.sha256(message);
    }
  }

  /**
   * SHA-256 hash returning base64 (for x-amz-checksum-sha256 header)
   */
  async sha256Base64(message) {
    if (hasSubtleCrypto) {
      const encoder = new TextEncoder();
      const data = encoder.encode(message);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const bytes = new Uint8Array(hashBuffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    } else {
      // Use CryptoJS - get bytes and convert to base64
      const bytes = CryptoJSWrapper.sha256Bytes(message);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }
  }

  /**
   * MD5 hash returning base64 (for Content-MD5 header)
   */
  md5Base64(message) {
    // MD5 is not available in Web Crypto API (not secure), so use CryptoJS
    const hash = CryptoJS.MD5(message);
    const bytes = [];
    for (let i = 0; i < hash.sigBytes; i++) {
      bytes.push((hash.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    }
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * HMAC-SHA256 (uses crypto.subtle in HTTPS, CryptoJS in HTTP)
   */
  async hmacSha256(key, message) {
    if (hasSubtleCrypto) {
      const encoder = new TextEncoder();
      const keyData = typeof key === 'string' ? encoder.encode(key) : key;
      const messageData = encoder.encode(message);

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );

      const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
      return new Uint8Array(signature);
    } else {
      return CryptoJSWrapper.hmacSha256(key, message);
    }
  }

  /**
   * Get signing key for AWS Signature V4
   */
  async getSigningKey(secretKey, dateStamp, region, service) {
    const encoder = new TextEncoder();
    const kDate = await this.hmacSha256(encoder.encode('AWS4' + secretKey), dateStamp);
    const kRegion = await this.hmacSha256(kDate, region);
    const kService = await this.hmacSha256(kRegion, service);
    const kSigning = await this.hmacSha256(kService, 'aws4_request');
    return kSigning;
  }

  /**
   * Format date for AWS signing
   */
  getAmzDate() {
    const now = new Date();
    return now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  }

  /**
   * Get date stamp (YYYYMMDD)
   */
  getDateStamp() {
    return this.getAmzDate().slice(0, 8);
  }

  /**
   * Sign a request using AWS Signature V4
   * @param {string} method - HTTP method
   * @param {string} path - Request path
   * @param {Object} queryParams - Query parameters
   * @param {string} body - Request body
   * @param {boolean} useAdminEndpoint - Use admin endpoint instead of S3
   * @param {string} contentType - Content type (signed for methods with a body)
   * @param {Object} extraSignedHeaders - Headers to include in the signature
   *   as well as the request, required for every x-amz-* header
   */
  async signRequest(method, path, queryParams = {}, body = '', useAdminEndpoint = false, contentType = 'application/xml', extraSignedHeaders = {}) {
    if (!this.credentials) {
      throw new Error('Not authenticated');
    }

    const fullUrl = this.buildRequestUrl(path, useAdminEndpoint);
    const url = new URL(fullUrl);
    const host = url.host;
    const service = 's3';
    const amzDate = this.getAmzDate();
    const dateStamp = this.getDateStamp();

    // Add query parameters
    Object.entries(queryParams).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, value);
      }
    });

    // Sort query parameters
    const sortedParams = [...url.searchParams.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    const canonicalQueryString = sortedParams.map(([k, v]) =>
      `${awsUriEncode(k)}=${awsUriEncode(v)}`
    ).join('&');

    // Hash the payload
    const payloadHash = await this.sha256(body);

    // Create canonical headers - only include content-type for methods with body
    const headers = {
      'host': host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
    };

    // Add Content-Type only for methods that have a body.
    // IMPORTANT: if the actual request sends a different Content-Type than the one
    // we sign, the gateway will return SignatureDoesNotMatch.
    const hasBody = method === 'PUT' || method === 'POST' || method === 'PATCH';
    if (hasBody && contentType) {
      headers['content-type'] = contentType;
    }

    Object.entries(extraSignedHeaders).forEach(([key, value]) => {
      headers[key.toLowerCase()] = String(value).trim();
    });

    const signedHeadersList = Object.keys(headers).sort();
    const signedHeaders = signedHeadersList.join(';');
    const canonicalHeaders = signedHeadersList.map(h => `${h}:${headers[h]}\n`).join('');

    // Create canonical request
    const canonicalRequest = [
      method,
      url.pathname,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    // Create string to sign
    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${this.region}/${service}/aws4_request`;
    const canonicalRequestHash = await this.sha256(canonicalRequest);
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      canonicalRequestHash
    ].join('\n');

    // Calculate signature
    const signingKey = await this.getSigningKey(this.credentials.secretKey, dateStamp, this.region, service);
    const signatureBuffer = await this.hmacSha256(signingKey, stringToSign);
    const signature = this.bufferToHex(signatureBuffer);

    // Create authorization header
    const authorization = `${algorithm} Credential=${this.credentials.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // Build response headers - only include Content-Type if it was signed
    const responseHeaders = {
      'Authorization': authorization,
      'X-Amz-Date': amzDate,
      'X-Amz-Content-Sha256': payloadHash,
    };

    if (hasBody && contentType) {
      responseHeaders['Content-Type'] = contentType;
    }

    Object.entries(extraSignedHeaders).forEach(([key, value]) => {
      responseHeaders[key] = String(value).trim();
    });

    return {
      url: url.toString(),
      headers: responseHeaders
    };
  }

  /**
   * Sign a request with x-amz-checksum-sha256 header (for S3 Multi-Object Delete)
   * @param {string} method - HTTP method
   * @param {string} path - Request path
   * @param {Object} queryParams - Query parameters
   * @param {string} body - Request body
   * @param {string} checksumBase64 - Base64-encoded SHA256 checksum of body
   */
  async signRequestWithChecksum(method, path, queryParams = {}, body = '', checksumBase64) {
    if (!this.credentials) {
      throw new Error('Not authenticated');
    }

    const fullUrl = this.buildRequestUrl(path, false);
    const url = new URL(fullUrl);
    const host = url.host;
    const service = 's3';
    const amzDate = this.getAmzDate();
    const dateStamp = this.getDateStamp();

    // Add query parameters
    Object.entries(queryParams).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, value);
      }
    });

    // Sort query parameters
    const sortedParams = [...url.searchParams.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    const canonicalQueryString = sortedParams.map(([k, v]) =>
      `${awsUriEncode(k)}=${awsUriEncode(v)}`
    ).join('&');

    // Hash the payload
    const payloadHash = await this.sha256(body);

    // Create canonical headers - include checksum and content-type (this is always POST with body)
    const headers = {
      'content-type': 'application/xml',
      'host': host,
      'x-amz-checksum-sha256': checksumBase64,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
    };

    const signedHeadersList = Object.keys(headers).sort();
    const signedHeaders = signedHeadersList.join(';');
    const canonicalHeaders = signedHeadersList.map(h => `${h}:${headers[h]}\n`).join('');

    // Create canonical request
    const canonicalRequest = [
      method,
      url.pathname,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    // Create string to sign
    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${this.region}/${service}/aws4_request`;
    const canonicalRequestHash = await this.sha256(canonicalRequest);
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      canonicalRequestHash
    ].join('\n');

    // Calculate signature
    const signingKey = await this.getSigningKey(this.credentials.secretKey, dateStamp, this.region, service);
    const signatureBuffer = await this.hmacSha256(signingKey, stringToSign);
    const signature = this.bufferToHex(signatureBuffer);

    // Create authorization header
    const authorization = `${algorithm} Credential=${this.credentials.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
      url: url.toString(),
      headers: {
        'Authorization': authorization,
        'X-Amz-Date': amzDate,
        'X-Amz-Content-Sha256': payloadHash,
        'X-Amz-Checksum-Sha256': checksumBase64,
        'Content-Type': 'application/xml',
      }
    };
  }

  /**
   * Make a signed API request
   * @param {string} method - HTTP method
   * @param {string} path - Request path
   * @param {Object} queryParams - Query parameters
   * @param {string} body - Request body
   * @param {boolean} useAdminEndpoint - Use admin endpoint instead of S3
   * @param {string} contentType - Content type for the request
   * @param {Object} additionalHeaders - Additional headers to include
   */
  async request(method, path, queryParams = {}, body = '', useAdminEndpoint = false, contentType = 'application/xml', additionalHeaders = {}, signal = null) {
    if (!this.credentials) {
      throw new Error('Not authenticated');
    }

    // Always sign and send directly to the configured endpoint.
    // CORS must be configured on the S3 endpoint.
    //
    // x-amz-* headers must be covered by the signature or the gateway
    // rejects the request; anything else rides along unsigned.
    const amzHeaders = {};
    const plainHeaders = {};
    Object.entries(additionalHeaders).forEach(([key, value]) => {
      (key.toLowerCase().startsWith('x-amz-') ? amzHeaders : plainHeaders)[key] = value;
    });

    const signed = await this.signRequest(method, path, queryParams, body, useAdminEndpoint, contentType, amzHeaders);
    const fetchUrl = signed.url;
    const headers = { ...signed.headers, ...plainHeaders };

    let response;
    try {
      response = await fetch(fetchUrl, {
        method,
        headers,
        body: body || undefined,
        signal: signal || undefined,
      });
    } catch (e) {
      // Browsers surface network-level failures (CORS, TLS/certificate errors,
      // unreachable host) as a generic TypeError with no further detail.
      if (e instanceof TypeError) {
        throw new Error(`Network error: cannot reach gateway. Common causes: CORS policy (gateway must allow origin ${window.location.origin}), TLS/certificate error (untrusted or self-signed certificate rejected by the browser), or the gateway is unreachable.`);
      }
      throw e;
    }

    const responseText = await response.text();

    if (!response.ok) {
      throw new Error(parseXmlErrorMessage(responseText, `HTTP ${response.status}: ${response.statusText}`));
    }

    return responseText;
  }

  /**
   * Build fetch parameters for a request
   * When proxy is available: uses server-side signing (credentials sent to vgwmgr, not S3 gateway)
   * When no proxy: uses browser-side signing
   * @param {string} method - HTTP method
   * @param {string} path - Request path
   * @param {Object} queryParams - Query parameters
   * @param {string} body - Request body
   * @param {boolean} useAdminEndpoint - Use admin endpoint instead of S3
   * @param {string} contentType - Optional content type override
   * @returns {Object} - { url, headers } for fetch
   */
  async buildFetchParams(method, path, queryParams = {}, body = '', useAdminEndpoint = false, contentType = 'application/xml') {
    if (!this.credentials) {
      throw new Error('Not authenticated');
    }

    // Build URL with query params
    const endpoint = useAdminEndpoint ? this.adminEndpoint : this.s3Endpoint;
    const url = new URL(endpoint + path);
    Object.entries(queryParams).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, value);
      }
    });

    const signed = await this.signRequest(method, path, queryParams, body, useAdminEndpoint, contentType);
    return {
      url: signed.url,
      headers: signed.headers,
    };
  }

  /**
   * Detect what the credentials can reach across all three configured
   * endpoints: S3 data plane, Admin API, and the standalone IAM service.
   * Every applicable probe runs, so one success does not mask another.
   *
   * Returns: 'admin' | 's3' | 'iam' | 'none'
   */
  async detectRole() {
    let hasS3 = false;
    let canListBuckets = false;
    let isAdmin = false;
    let hasIAM = false;
    let networkError = null;

    const isNetworkError = (e) =>
      e && typeof e.message === 'string' && e.message.startsWith('Network error:');

    // 1. S3 data plane. An unconfigured endpoint is an IAM-only sign-in, not
    // a failure, so skip the probe rather than rejecting the credentials.
    //
    // ListBuckets needs s3:ListAllMyBuckets, which a user scoped to named
    // buckets may lack while still being able to use the Explorer. Only
    // AccessDenied draws that line: it comes back after the signature and
    // account checks pass, unlike the other HTTP 403s
    // (InvalidAccessKeyId/SignatureDoesNotMatch/ExpiredToken), which mean the
    // credentials themselves were rejected.
    if (this.s3Endpoint) {
      try {
        await this.listBucketsS3();
        hasS3 = true;
        canListBuckets = true;
      } catch (s3Error) {
        if (isNetworkError(s3Error)) {
          networkError = s3Error;
        } else if (s3Error.code === 'AccessDenied') {
          hasS3 = true;
          canListBuckets = false;
        }
      }
    }

    // 2. Admin API — only meaningful once S3 access is established. All admin
    // routes share the same role gate, so probe with list-buckets: list-users
    // also needs an IAM backend that can enumerate accounts, which the
    // standalone IAM backend cannot.
    if (hasS3 && this.adminEndpoint) {
      try {
        await this.listBuckets();
        isAdmin = true;
        // Admin/root always bypasses the ListAllMyBuckets policy check.
        canListBuckets = true;
      } catch (adminError) {
        // Expected for non-admin accounts
      }
    }

    // 3. Standalone IAM service. GetCallerIdentity needs no policy grant, so
    // it is the only action any valid credential is sure to be allowed.
    let iamProbeError = null;
    if (this.iamEndpoint) {
      try {
        await this.iamGetCallerIdentity();
        hasIAM = true;
      } catch (iamError) {
        iamProbeError = iamError;
        if (isNetworkError(iamError) && !networkError) networkError = iamError;
      }
    }

    if (!hasS3 && !hasIAM) {
      // Surface a network-level diagnostic instead of a plain auth failure.
      if (networkError) throw networkError;
      return 'none';
    }

    // At least one source accepted the credentials, so a network failure on
    // another is logged rather than failing an otherwise valid session.
    if (networkError) console.warn(networkError.message);

    this.setAdminRole(isAdmin);
    this.setHasIAM(hasIAM);
    this.setHasS3(hasS3);
    this.setCanListBuckets(canListBuckets);

    // A configured IAM endpoint that did not answer is worth saying out loud:
    // the usual cause is a missing --cors-allow-origin, whose only other
    // symptom is an IAM tab that never appears.
    sessionStorage.removeItem('vgw_iam_probe_error');
    if (iamProbeError && !hasIAM) {
      sessionStorage.setItem('vgw_iam_probe_error', iamProbeError.message);
    }

    if (isAdmin) return 'admin';
    if (hasS3) return 's3';
    return 'iam';
  }

  // ============================================
  // Admin API Methods
  // ============================================

  /**
   * Parse XML list response to array
   */
  parseXmlList(xmlString, itemTag) {
    if (!xmlString.trim()) return [];

    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlString, 'text/xml');

    // Check for parsing errors
    const parseError = xmlDoc.querySelector('parsererror');
    if (parseError) {
      console.error('XML Parse Error:', parseError.textContent);
      return [];
    }

    const items = xmlDoc.querySelectorAll(itemTag);
    return Array.from(items).map(item => {
      const obj = {};
      Array.from(item.children).forEach(child => {
        obj[child.tagName.toLowerCase()] = child.textContent;
      });
      return obj;
    });
  }

  /**
   * List all users (Admin API)
   */
  async listUsers() {
    const response = await this.request('PATCH', '/list-users', {}, '', true);
    // VersityGW returns XML with <Accounts> tags
    return this.parseXmlList(response, 'Accounts');
  }

  /**
   * Create a new user (Admin API)
   */
  async createUser(access, secret, role, userID = 0, groupID = 0, projectID = 0) {
    const body = `<?xml version="1.0" encoding="UTF-8"?>
<Account>
  <Access>${this.escapeXml(access)}</Access>
  <Secret>${this.escapeXml(secret)}</Secret>
  <Role>${this.escapeXml(role)}</Role>
  <UserID>${userID}</UserID>
  <GroupID>${groupID}</GroupID>
  <ProjectID>${projectID}</ProjectID>
</Account>`;

    await this.request('PATCH', '/create-user', {}, body, true);
  }

  /**
   * Update an existing user (Admin API)
   */
  async updateUser(access, updates) {
    let body = '<?xml version="1.0" encoding="UTF-8"?>\n<MutableProps>';

    if (updates.secret !== undefined) {
      body += `\n  <Secret>${this.escapeXml(updates.secret)}</Secret>`;
    }
    if (updates.role !== undefined) {
      body += `\n  <Role>${this.escapeXml(updates.role)}</Role>`;
    }
    if (updates.userID !== undefined) {
      body += `\n  <UserID>${updates.userID}</UserID>`;
    }
    if (updates.groupID !== undefined) {
      body += `\n  <GroupID>${updates.groupID}</GroupID>`;
    }
    if (updates.projectID !== undefined) {
      body += `\n  <ProjectID>${updates.projectID}</ProjectID>`;
    }

    body += '\n</MutableProps>';

    await this.request('PATCH', '/update-user', { access }, body, true);
  }

  /**
   * Delete a user (Admin API)
   */
  async deleteUser(access) {
    await this.request('PATCH', '/delete-user', { access }, '', true);
  }

  /**
   * List all buckets (Admin API - returns all buckets with owner info)
   */
  async listBuckets() {
    const response = await this.request('PATCH', '/list-buckets', {}, '', true);
    // VersityGW returns XML - check for Buckets or Bucket tags
    let buckets = this.parseXmlList(response, 'Buckets');
    if (buckets.length === 0) {
      buckets = this.parseXmlList(response, 'Bucket');
    }
    return buckets;
  }

  /**
   * Change bucket owner (Admin API)
   */
  async changeBucketOwner(bucket, owner) {
    await this.request('PATCH', '/change-bucket-owner', { bucket, owner }, '', true);
  }

  // ============================================
  // S3 Standard API Methods
  // ============================================

  /**
   * List buckets via standard S3 API (for non-admin users)
   * Returns buckets the user has access to
   */
  async listBucketsS3() {
    // Use presigned URL to avoid triggering a browser preflight for GET /.
    const presignedUrl = await this.presignUrl('GET', '/', {}, 60, false);
    let httpResponse;
    try {
      httpResponse = await fetch(presignedUrl, { method: 'GET' });
    } catch (e) {
      // Browsers surface network-level failures (CORS, TLS/certificate errors,
      // unreachable host) as a generic TypeError with no further detail.
      if (e instanceof TypeError) {
        throw new Error(`Network error: cannot reach gateway. Common causes: CORS policy (gateway must allow origin ${window.location.origin}), TLS/certificate error (untrusted or self-signed certificate rejected by the browser), or the gateway is unreachable.`);
      }
      throw e;
    }
    const response = await httpResponse.text();

    if (!httpResponse.ok) {
      // Try to parse error from XML
      let errorMessage = `HTTP ${httpResponse.status}: ${httpResponse.statusText}`;
      let code = null;
      try {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(response, 'text/xml');
        code = xmlDoc.querySelector('Code')?.textContent || null;
        const message = xmlDoc.querySelector('Message')?.textContent;
        if (code) errorMessage = `${code}: ${message || 'Unknown error'}`;
      } catch (e) {
        // Ignore parsing errors
      }
      const err = new Error(errorMessage);
      // Both are HTTP 403, so the code is what tells "credentials rejected"
      // apart from "credentials valid, action forbidden" (AccessDenied).
      err.status = httpResponse.status;
      err.code = code;
      throw err;
    }

    const parser = new DOMParser();
    const doc = parser.parseFromString(response, 'text/xml');

    const buckets = [];
    doc.querySelectorAll('Bucket').forEach(bucket => {
      buckets.push({
        name: bucket.querySelector('Name')?.textContent || '',
        creationdate: bucket.querySelector('CreationDate')?.textContent || ''
      });
    });

    return buckets;
  }

  /**
   * Create a new bucket with owner and settings (Admin API)
   * @param {string} bucketName - The name of the bucket to create
   * @param {string} owner - The access key ID of the bucket owner
   * @param {boolean} enableVersioning - Whether to enable versioning
   * @param {boolean} enableObjectLock - Whether to enable object lock
   */
  async createBucketWithOwner(bucketName, owner, enableVersioning = false, enableObjectLock = false) {
    if (!owner) {
      throw new Error('Owner access key ID is required');
    }

    // Build the request with custom headers for the admin API
    const headers = {
      'x-vgw-owner': owner,
    };

    // Add object lock header if enabled
    if (enableObjectLock) {
      headers['x-amz-bucket-object-lock-enabled'] = 'true';
    }

    // Create the bucket using the admin API endpoint
    const response = await this.request(
      'PATCH',
      `/${bucketName}/create`,
      {},
      '',
      true,  // useAdminEndpoint
      'application/xml',
      headers
    );

    // If versioning is enabled (but not object lock, as object lock enables versioning automatically)
    // we need to call PutBucketVersioning after bucket creation
    if (enableVersioning && !enableObjectLock) {
      try {
        await this.putBucketVersioning(bucketName, 'Enabled');
      } catch (error) {
        console.warn('Failed to enable versioning after bucket creation:', error);
        // Don't throw - bucket was created successfully
      }
    }
  }

  /**
   * Create a new bucket with bucket name(s3api)
   * @param {string} bucketName - The name of the bucket to create
   * @param {boolean} enableObjectLock - Whether to enable object lock
   *   (which enables versioning as well)
   */
  async createBucket(bucketName, enableObjectLock = false) {
    if (!bucketName) {
      throw new Error('Bucket name is required');
    }

    const headers = {};
    if (enableObjectLock) {
      headers['x-amz-bucket-object-lock-enabled'] = 'true';
    }

    await this.request(
      'PUT',
      `/${bucketName}`,
      {},
      '',
      false,
      'application/xml',
      headers
    );
  }

  /**
   * Delete a bucket (S3 DeleteBucket)
   */
  async deleteBucket(bucketName) {
    const fetchParams = await this.buildFetchParams('DELETE', `/${bucketName}`, {}, '');
    const response = await fetch(fetchParams.url, {
      method: 'DELETE',
      headers: fetchParams.headers,
    });

    if (!response.ok) {
      const text = await response.text();
      const messageMatch = text.match(/<Message>([^<]+)<\/Message>/);
      throw new Error(messageMatch ? messageMatch[1] : `Failed to delete bucket (${response.status})`);
    }
  }

  /**
   * List objects in a bucket (S3 ListObjectsV2)
   */
  async listObjectsV2(bucket, prefix = '', delimiter = '/', maxKeys = 1000, continuationToken = null, signal = null) {
    const params = {
      'list-type': '2',
      'prefix': prefix,
      'delimiter': delimiter,
      'max-keys': maxKeys.toString()
    };

    if (continuationToken) {
      params['continuation-token'] = continuationToken;
    }

    const response = await this.request('GET', `/${bucket}`, params, '', false, 'application/xml', {}, signal);
    return this.parseListObjectsV2Response(response);
  }

  /**
   * Parse ListObjectsV2 XML response
   */
  parseListObjectsV2Response(xmlString) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlString, 'text/xml');

    const result = {
      name: doc.querySelector('Name')?.textContent || '',
      prefix: doc.querySelector('Prefix')?.textContent || '',
      delimiter: doc.querySelector('Delimiter')?.textContent || '',
      isTruncated: doc.querySelector('IsTruncated')?.textContent === 'true',
      continuationToken: doc.querySelector('NextContinuationToken')?.textContent || null,
      contents: [],
      commonPrefixes: []
    };

    // Parse Contents (files)
    doc.querySelectorAll('Contents').forEach(item => {
      result.contents.push({
        key: item.querySelector('Key')?.textContent || '',
        lastModified: item.querySelector('LastModified')?.textContent || '',
        size: parseInt(item.querySelector('Size')?.textContent || '0', 10),
        storageClass: item.querySelector('StorageClass')?.textContent || 'STANDARD',
        etag: item.querySelector('ETag')?.textContent || ''
      });
    });

    // Parse CommonPrefixes (folders)
    doc.querySelectorAll('CommonPrefixes').forEach(item => {
      result.commonPrefixes.push({
        prefix: item.querySelector('Prefix')?.textContent || ''
      });
    });

    return result;
  }

  /**
   * Get object metadata (HeadObject)
   */
  async headObject(bucket, key) {
    const fetchParams = await this.buildFetchParams('HEAD', `/${bucket}/${encodeS3Key(key)}`);

    const response = await fetch(fetchParams.url, {
      method: 'HEAD',
      headers: fetchParams.headers,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return {
      contentLength: parseInt(response.headers.get('Content-Length') || '0', 10),
      contentType: response.headers.get('Content-Type') || 'application/octet-stream',
      lastModified: response.headers.get('Last-Modified') || '',
      etag: response.headers.get('ETag') || '',
      storageClass: response.headers.get('x-amz-storage-class') || 'STANDARD',
      metadata: this.extractMetadataHeaders(response.headers)
    };
  }

  /**
   * Extract x-amz-meta-* headers as metadata object
   */
  extractMetadataHeaders(headers) {
    const metadata = {};
    headers.forEach((value, key) => {
      if (key.toLowerCase().startsWith('x-amz-meta-')) {
        const metaKey = key.substring(11); // Remove 'x-amz-meta-' prefix
        metadata[metaKey] = value;
      }
    });
    return metadata;
  }

  /**
   * Download an object (GetObject)
   * Returns a Blob for browser download
   */
  async getObject(bucket, key) {
    const fetchParams = await this.buildFetchParams('GET', `/${bucket}/${encodeS3Key(key)}`);

    const response = await fetch(fetchParams.url, {
      method: 'GET',
      headers: fetchParams.headers,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return {
      blob: await response.blob(),
      contentType: response.headers.get('Content-Type') || 'application/octet-stream',
      contentLength: parseInt(response.headers.get('Content-Length') || '0', 10)
    };
  }

  /**
   * Upload an object (PutObject) - for small files < 5MB
   */
  async putObject(bucket, key, file, contentType = null) {
    const finalContentType = contentType || file.type || 'application/octet-stream';
    const path = `/${bucket}/${encodeS3Key(key)}`;

    // Browser-side signing with payload hash
    const arrayBuffer = await file.arrayBuffer();
    const payloadHash = await this.sha256ArrayBuffer(arrayBuffer);
    const signed = await this.signRequestWithPayloadHash('PUT', path, {}, payloadHash, finalContentType);

    const response = await fetch(signed.url, {
      method: 'PUT',
      headers: signed.headers,
      body: file,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Upload failed: HTTP ${response.status} - ${errorText}`);
    }

    return { etag: response.headers.get('ETag') || '' };
  }

  /**
   * SHA-256 hash of ArrayBuffer
   */
  async sha256ArrayBuffer(buffer) {
    if (hasSubtleCrypto) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      return this.bufferToHex(hashBuffer);
    } else {
      // Convert ArrayBuffer to CryptoJS WordArray for proper binary hashing
      const bytes = new Uint8Array(buffer);
      const words = [];
      for (let i = 0; i < bytes.length; i += 4) {
        const word = (bytes[i] << 24) | ((bytes[i + 1] || 0) << 16) | ((bytes[i + 2] || 0) << 8) | (bytes[i + 3] || 0);
        words.push(word);
      }
      const wordArray = CryptoJS.lib.WordArray.create(words, bytes.length);
      return CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);
    }
  }

  /**
   * Sign request with pre-computed payload hash (for binary uploads)
   */
  async signRequestWithPayloadHash(method, path, queryParams = {}, payloadHash, contentType) {
    if (!this.credentials) {
      throw new Error('Not authenticated');
    }

    const fullUrl = this.buildRequestUrl(path, false);
    const url = new URL(fullUrl);
    const host = url.host;
    const service = 's3';
    const amzDate = this.getAmzDate();
    const dateStamp = this.getDateStamp();

    // Add query parameters
    Object.entries(queryParams).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, value);
      }
    });

    // Sort query parameters
    const sortedParams = [...url.searchParams.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    const canonicalQueryString = sortedParams.map(([k, v]) =>
      `${awsUriEncode(k)}=${awsUriEncode(v)}`
    ).join('&');

    // Create canonical headers
    const headers = {
      'content-type': contentType,
      'host': host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
    };

    const signedHeadersList = Object.keys(headers).sort();
    const signedHeaders = signedHeadersList.join(';');
    const canonicalHeaders = signedHeadersList.map(h => `${h}:${headers[h]}\n`).join('');

    // Create canonical request
    const canonicalRequest = [
      method,
      url.pathname,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    // Create string to sign
    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${this.region}/${service}/aws4_request`;
    const canonicalRequestHash = await this.sha256(canonicalRequest);
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      canonicalRequestHash
    ].join('\n');

    // Calculate signature
    const signingKey = await this.getSigningKey(this.credentials.secretKey, dateStamp, this.region, service);
    const signatureBuffer = await this.hmacSha256(signingKey, stringToSign);
    const signature = this.bufferToHex(signatureBuffer);

    // Create authorization header
    const authorization = `${algorithm} Credential=${this.credentials.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
      url: url.toString(),
      headers: {
        'Authorization': authorization,
        'X-Amz-Date': amzDate,
        'X-Amz-Content-Sha256': payloadHash,
        'Content-Type': contentType,
      }
    };
  }

  /**
   * Delete an object
   */
  async deleteObject(bucket, key) {
    await this.request('DELETE', `/${bucket}/${encodeS3Key(key)}`);
  }

  /**
   * Delete multiple objects (batch delete)
   * S3 Multi-Object Delete requires x-amz-checksum-* or Content-MD5 header
   */
  async deleteObjects(bucket, keys) {
    let body = '<?xml version="1.0" encoding="UTF-8"?>\n<Delete>';
    body += '\n  <Quiet>true</Quiet>';

    keys.forEach(key => {
      body += `\n  <Object>\n    <Key>${this.escapeXml(key)}</Key>\n  </Object>`;
    });

    body += '\n</Delete>';

    const checksum = await this.sha256Base64(body);
    const signed = await this.signRequestWithChecksum('POST', `/${bucket}`, { delete: '' }, body, checksum);

    const response = await fetch(signed.url, {
      method: 'POST',
      headers: signed.headers,
      body: body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Delete failed: ${errorText}`);
    }

    return await response.text();
  }

  /**
   * Create a folder (empty object with trailing slash)
   */
  async createFolder(bucket, prefix) {
    // Ensure prefix ends with /
    const folderKey = prefix.endsWith('/') ? prefix : prefix + '/';

    const fetchParams = await this.buildFetchParams('PUT', `/${bucket}/${encodeS3Key(folderKey)}`, {}, '');

    const response = await fetch(fetchParams.url, {
      method: 'PUT',
      headers: fetchParams.headers,
      body: '',
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Create folder failed: ${errorText}`);
    }
  }

  // ============================================
  // Multipart Upload Methods
  // ============================================

  /**
   * Initiate a multipart upload
   * Returns uploadId needed for subsequent parts
   */
  async createMultipartUpload(bucket, key, contentType = 'application/octet-stream') {
    const fetchParams = await this.buildFetchParams('POST', `/${bucket}/${encodeS3Key(key)}`, { uploads: '' }, '', false, contentType);

    const response = await fetch(fetchParams.url, {
      method: 'POST',
      headers: fetchParams.headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to initiate multipart upload: ${errorText}`);
    }

    const xmlText = await response.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlText, 'text/xml');
    const uploadId = doc.querySelector('UploadId')?.textContent;

    if (!uploadId) {
      throw new Error('No UploadId returned from server');
    }

    return uploadId;
  }

  /**
   * Upload a single part of a multipart upload
   * Returns ETag needed for CompleteMultipartUpload
   */
  async uploadPart(bucket, key, uploadId, partNumber, data) {
    const arrayBuffer = data instanceof ArrayBuffer ? data : await data.arrayBuffer();
    const path = `/${bucket}/${encodeS3Key(key)}`;
    const queryParams = {
      uploadId: uploadId,
      partNumber: partNumber.toString()
    };

    const payloadHash = await this.sha256ArrayBuffer(arrayBuffer);
    const signed = await this.signRequestWithPayloadHash(
      'PUT',
      path,
      queryParams,
      payloadHash,
      'application/octet-stream'
    );

    const response = await fetch(signed.url, {
      method: 'PUT',
      headers: signed.headers,
      body: arrayBuffer,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to upload part ${partNumber}: ${errorText}`);
    }

    // Try multiple ways to get ETag (CORS may not expose all headers)
    let etag = response.headers.get('ETag')
            || response.headers.get('etag')
            || response.headers.get('x-amz-etag');

    // If still no ETag, try to read from response body (some proxies put it there)
    if (!etag) {
      const text = await response.clone().text();
      const match = text.match(/<ETag>([^<]+)<\/ETag>/i);
      if (match) {
        etag = match[1];
      }
    }

    if (!etag) {
      // Log all available headers for debugging
      console.warn('Available headers:', [...response.headers.entries()]);
      throw new Error(`No ETag returned for part ${partNumber}. The server may need to expose ETag in CORS headers (Access-Control-Expose-Headers: ETag).`);
    }

    return etag;
  }

  /**
   * Complete a multipart upload
   * parts should be an array of { partNumber, etag }
   */
  async completeMultipartUpload(bucket, key, uploadId, parts) {
    let body = '<?xml version="1.0" encoding="UTF-8"?>\n<CompleteMultipartUpload>';

    // Sort parts by partNumber
    parts.sort((a, b) => a.partNumber - b.partNumber);

    parts.forEach(part => {
      body += `\n  <Part>`;
      body += `\n    <PartNumber>${part.partNumber}</PartNumber>`;
      body += `\n    <ETag>${this.escapeXml(part.etag)}</ETag>`;
      body += `\n  </Part>`;
    });

    body += '\n</CompleteMultipartUpload>';

    const fetchParams = await this.buildFetchParams('POST', `/${bucket}/${encodeS3Key(key)}`, { uploadId }, body);

    const response = await fetch(fetchParams.url, {
      method: 'POST',
      headers: fetchParams.headers,
      body: body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to complete multipart upload: ${errorText}`);
    }

    return await response.text();
  }

  /**
   * Abort a multipart upload
   */
  async abortMultipartUpload(bucket, key, uploadId) {
    const fetchParams = await this.buildFetchParams('DELETE', `/${bucket}/${encodeS3Key(key)}`, { uploadId }, '');

    const response = await fetch(fetchParams.url, {
      method: 'DELETE',
      headers: fetchParams.headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to abort multipart upload: ${errorText}`);
    }
  }

  /**
   * List multipart uploads in a bucket
   * @param {string} bucket - Bucket name
   * @returns {Promise<Array>} - Array of multipart upload objects
   */
  async listMultipartUploads(bucket) {
    const response = await this.request('GET', `/${bucket}`, { uploads: '' });
    const parser = new DOMParser();
    const doc = parser.parseFromString(response, 'text/xml');
    
    const uploads = [];
    doc.querySelectorAll('Upload').forEach(upload => {
      uploads.push({
        key: upload.querySelector('Key')?.textContent || '',
        uploadId: upload.querySelector('UploadId')?.textContent || '',
        initiated: upload.querySelector('Initiated')?.textContent || '',
        initiator: upload.querySelector('Initiator DisplayName')?.textContent || '',
        owner: upload.querySelector('Owner DisplayName')?.textContent || ''
      });
    });
    
    return uploads;
  }

  // ============================================
  // Bucket Versioning Methods
  // ============================================

  /**
   * Get versioning status for a bucket
   * Returns: { status: 'Enabled' | 'Suspended' | '' }
   */
  async getBucketVersioning(bucket) {
    const response = await this.request('GET', `/${bucket}`, { versioning: '' });
    const parser = new DOMParser();
    const doc = parser.parseFromString(response, 'text/xml');
    return {
      status: doc.querySelector('Status')?.textContent || ''
    };
  }

  /**
   * Set versioning status for a bucket
   * @param {string} bucket - Bucket name
   * @param {string} status - 'Enabled' or 'Suspended'
   */
  async putBucketVersioning(bucket, status) {
    const body = `<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>${this.escapeXml(status)}</Status>
</VersioningConfiguration>`;
    await this.request('PUT', `/${bucket}`, { versioning: '' }, body);
  }

  /**
   * Get object lock configuration for a bucket
   * Returns: { enabled: boolean, mode: string, days: number, years: number }
   */
  async getBucketObjectLockConfiguration(bucket) {
    try {
      const response = await this.request('GET', `/${bucket}`, { 'object-lock': '' });
      const parser = new DOMParser();
      const doc = parser.parseFromString(response, 'text/xml');
      
      const enabled = doc.querySelector('ObjectLockEnabled')?.textContent === 'Enabled';
      const rule = doc.querySelector('Rule');
      let mode = '';
      let days = null;
      let years = null;
      
      if (rule) {
        mode = rule.querySelector('Mode')?.textContent || '';
        days = rule.querySelector('Days')?.textContent;
        years = rule.querySelector('Years')?.textContent;
      }
      
      return {
        enabled,
        mode,
        days: days ? parseInt(days) : null,
        years: years ? parseInt(years) : null
      };
    } catch (error) {
      // If object lock is not configured or not supported, return disabled status
      if (error.message.includes('ObjectLockConfigurationNotFoundError') || 
          error.message.includes('405') || 
          error.message.includes('501')) {
        return { enabled: false, mode: '', days: null, years: null };
      }
      throw error;
    }
  }

  /**
   * Enable or update object lock configuration for a bucket
   * @param {string} bucket - Bucket name
   * @param {Object} config - { mode: 'GOVERNANCE'|'COMPLIANCE', days: number, years: number }
   */
  async putBucketObjectLockConfiguration(bucket, config) {
    let ruleXml = '';
    if (config.mode && (config.days || config.years)) {
      const retention = config.days ? `<Days>${config.days}</Days>` : `<Years>${config.years}</Years>`;
      ruleXml = `
  <Rule>
    <DefaultRetention>
      <Mode>${this.escapeXml(config.mode)}</Mode>
      ${retention}
    </DefaultRetention>
  </Rule>`;
    }

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>${ruleXml}
</ObjectLockConfiguration>`;
    
    // Calculate Content-MD5 header
    const contentMd5 = this.md5Base64(body);

    await this.request('PUT', `/${bucket}`, { 'object-lock': '' }, body, false, 'application/xml', {
      'Content-MD5': contentMd5
    });
  }

  /**
   * List all versions of objects in a bucket
   */
  async listObjectVersions(bucket, prefix = '', delimiter = '/', maxKeys = 1000, keyMarker = null, versionIdMarker = null, signal = null) {
    const params = {
      versions: '',
      prefix: prefix,
      delimiter: delimiter,
      'max-keys': maxKeys.toString()
    };

    if (keyMarker) params['key-marker'] = keyMarker;
    if (versionIdMarker) params['version-id-marker'] = versionIdMarker;

    const response = await this.request('GET', `/${bucket}`, params, '', false, 'application/xml', {}, signal);
    return this.parseListObjectVersionsResponse(response);
  }

  /**
   * Parse ListObjectVersions XML response
   */
  parseListObjectVersionsResponse(xmlString) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlString, 'text/xml');

    const result = {
      name: doc.querySelector('Name')?.textContent || '',
      prefix: doc.querySelector('Prefix')?.textContent || '',
      isTruncated: doc.querySelector('IsTruncated')?.textContent === 'true',
      nextKeyMarker: doc.querySelector('NextKeyMarker')?.textContent || null,
      nextVersionIdMarker: doc.querySelector('NextVersionIdMarker')?.textContent || null,
      versions: [],
      deleteMarkers: [],
      commonPrefixes: []
    };

    // Parse object versions
    doc.querySelectorAll('Version').forEach(v => {
      result.versions.push({
        key: v.querySelector('Key')?.textContent || '',
        versionId: v.querySelector('VersionId')?.textContent || '',
        isLatest: v.querySelector('IsLatest')?.textContent === 'true',
        lastModified: v.querySelector('LastModified')?.textContent || '',
        size: parseInt(v.querySelector('Size')?.textContent || '0', 10),
        storageClass: v.querySelector('StorageClass')?.textContent || 'STANDARD',
        etag: v.querySelector('ETag')?.textContent || ''
      });
    });

    // Parse delete markers
    doc.querySelectorAll('DeleteMarker').forEach(dm => {
      result.deleteMarkers.push({
        key: dm.querySelector('Key')?.textContent || '',
        versionId: dm.querySelector('VersionId')?.textContent || '',
        isLatest: dm.querySelector('IsLatest')?.textContent === 'true',
        lastModified: dm.querySelector('LastModified')?.textContent || '',
        isDeleteMarker: true
      });
    });

    // Parse common prefixes (folders)
    doc.querySelectorAll('CommonPrefixes').forEach(cp => {
      result.commonPrefixes.push({
        prefix: cp.querySelector('Prefix')?.textContent || ''
      });
    });

    return result;
  }

  /**
   * Delete a specific version of an object
   */
  async deleteObjectVersion(bucket, key, versionId) {
    await this.request('DELETE', `/${bucket}/${encodeS3Key(key)}`, { versionId });
  }

  /**
   * Download a specific version of an object
   */
  async getObjectVersion(bucket, key, versionId) {
    const fetchParams = await this.buildFetchParams('GET', `/${bucket}/${encodeS3Key(key)}`, { versionId });

    const response = await fetch(fetchParams.url, {
      method: 'GET',
      headers: fetchParams.headers,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return {
      blob: await response.blob(),
      contentType: response.headers.get('Content-Type') || 'application/octet-stream'
    };
  }

  /**
   * Restore an old version by copying it to create a new current version
   */
  async restoreObjectVersion(bucket, key, versionId) {
    const copySource = `/${bucket}/${encodeS3Key(key)}?versionId=${versionId}`;

    const fetchParams = this.buildFetchParams('PUT', `/${bucket}/${encodeS3Key(key)}`, {}, '');
    fetchParams.headers['x-amz-copy-source'] = copySource;

    const response = await fetch(fetchParams.url, {
      method: 'PUT',
      headers: fetchParams.headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Restore failed: ${errorText}`);
    }
  }

  // ============================================
  // Bucket Tagging Methods
  // ============================================

  /**
   * Get bucket tags
   * Returns: Array of { key, value } objects
   */
  async getBucketTagging(bucket) {
    try {
      const response = await this.request('GET', `/${bucket}`, { tagging: '' });
      const parser = new DOMParser();
      const doc = parser.parseFromString(response, 'text/xml');
      
      const tags = [];
      doc.querySelectorAll('Tag').forEach(tagElement => {
        const key = tagElement.querySelector('Key')?.textContent || '';
        const value = tagElement.querySelector('Value')?.textContent || '';
        if (key) {
          tags.push({ key, value });
        }
      });
      
      return tags;
    } catch (error) {
      // If tagging is not configured, return empty array
      if (error.message.includes('404') || error.message.includes('NoSuchTagSet')) {
        return [];
      }
      throw error;
    }
  }

  /**
   * Set bucket tags
   * @param {string} bucket - Bucket name
   * @param {Array<{key: string, value: string}>} tags - Array of tag objects
   */
  async putBucketTagging(bucket, tags) {
    if (!tags || tags.length === 0) {
      // Delete all tags if empty
      return await this.deleteBucketTagging(bucket);
    }

    const tagsXml = tags.map(tag => 
      `    <Tag>\n      <Key>${this.escapeXml(tag.key)}</Key>\n      <Value>${this.escapeXml(tag.value)}</Value>\n    </Tag>`
    ).join('\n');

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <TagSet>
${tagsXml}
  </TagSet>
</Tagging>`;
    
    await this.request('PUT', `/${bucket}`, { tagging: '' }, body);
  }

  /**
   * Delete all bucket tags
   * @param {string} bucket - Bucket name
   */
  async deleteBucketTagging(bucket) {
    await this.request('DELETE', `/${bucket}`, { tagging: '' });
  }

  /**
   * Get bucket policy
   * @param {string} bucket - Bucket name
   * @returns {Promise<Object>} - Policy document as JSON object
   */
  async getBucketPolicy(bucket) {
    const response = await this.request('GET', `/${bucket}`, { policy: '' });
    try {
      return JSON.parse(response);
    } catch (error) {
      throw new Error('Failed to parse bucket policy: ' + error.message);
    }
  }

  /**
   * Put bucket policy
   * @param {string} bucket - Bucket name
   * @param {Object} policy - Policy document as JSON object
   */
  async putBucketPolicy(bucket, policy) {
    const policyJson = JSON.stringify(policy);
    await this.request('PUT', `/${bucket}`, { policy: '' }, policyJson, false, 'application/json');
  }

  /**
   * Delete bucket policy
   * @param {string} bucket - Bucket name
   */
  async deleteBucketPolicy(bucket) {
    await this.request('DELETE', `/${bucket}`, { policy: '' });
  }

  /**
   * Get object tags
   * @param {string} bucket - Bucket name
   * @param {string} key - Object key
   * @returns {Promise<Array<{key: string, value: string}>>} - Array of tag objects
   */
  async getObjectTagging(bucket, key) {
    try {
      const response = await this.request('GET', `/${bucket}/${encodeS3Key(key)}`, { tagging: '' });
      const parser = new DOMParser();
      const doc = parser.parseFromString(response, 'text/xml');
      
      const tags = [];
      doc.querySelectorAll('Tag').forEach(tagElement => {
        const tagKey = tagElement.querySelector('Key')?.textContent || '';
        const tagValue = tagElement.querySelector('Value')?.textContent || '';
        if (tagKey) {
          tags.push({ key: tagKey, value: tagValue });
        }
      });
      
      return tags;
    } catch (error) {
      // If tagging is not configured, return empty array
      if (error.message.includes('404') || error.message.includes('NoSuchTagSet')) {
        return [];
      }
      throw error;
    }
  }

  /**
   * Set object tags
   * @param {string} bucket - Bucket name
   * @param {string} key - Object key
   * @param {Array<{key: string, value: string}>} tags - Array of tag objects
   */
  async putObjectTagging(bucket, key, tags) {
    if (!tags || tags.length === 0) {
      // Delete all tags if empty
      return await this.deleteObjectTagging(bucket, key);
    }

    const tagsXml = tags.map(tag => 
      `    <Tag>\n      <Key>${this.escapeXml(tag.key)}</Key>\n      <Value>${this.escapeXml(tag.value)}</Value>\n    </Tag>`
    ).join('\n');

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <TagSet>
${tagsXml}
  </TagSet>
</Tagging>`;
    
    await this.request('PUT', `/${bucket}/${encodeS3Key(key)}`, { tagging: '' }, body);
  }

  /**
   * Delete all object tags
   * @param {string} bucket - Bucket name
   * @param {string} key - Object key
   */
  async deleteObjectTagging(bucket, key) {
    await this.request('DELETE', `/${bucket}/${encodeS3Key(key)}`, { tagging: '' });
  }

  /**
   * Update object metadata using CopyObject with REPLACE directive
   * @param {string} bucket - Bucket name
   * @param {string} key - Object key
   * @param {Object} metadata - Metadata key-value pairs (will be prefixed with x-amz-meta-)
   * @param {string} contentType - Optional content type override
   */
  async putObjectMetadata(bucket, key, metadata, contentType = null) {
    if (!this.credentials) {
      throw new Error('Not authenticated');
    }

    const method = 'PUT';
    const path = `/${bucket}/${encodeS3Key(key)}`;
    const endpoint = this.getEndpoint(false);
    const url = new URL(endpoint + path);
    const host = url.host;
    const service = 's3';
    const amzDate = this.getAmzDate();
    const dateStamp = this.getDateStamp();

    // CopyObject has no body
    const body = '';
    const payloadHash = await this.sha256(body);

    // Build all headers that need to be signed
    // IMPORTANT: x-amz-copy-source must be URL-encoded
    const copySource = `/${bucket}/${encodeS3Key(key)}`;
    
    const headers = {
      'host': host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-copy-source': copySource,
      'x-amz-date': amzDate,
      'x-amz-metadata-directive': 'REPLACE'
    };

    // Add metadata headers with x-amz-meta- prefix
    if (metadata) {
      for (const [metaKey, metaValue] of Object.entries(metadata)) {
        headers[`x-amz-meta-${metaKey}`] = metaValue;
      }
    }

    // Add content type if specified
    if (contentType) {
      headers['content-type'] = contentType;
    }

    // Sort headers for canonical request (case-insensitive)
    const signedHeadersList = Object.keys(headers).map(h => h.toLowerCase()).sort();
    const signedHeaders = signedHeadersList.join(';');
    
    // Create canonical headers (must be lowercase)
    const canonicalHeaders = signedHeadersList.map(h => {
      const originalKey = Object.keys(headers).find(k => k.toLowerCase() === h);
      return `${h}:${headers[originalKey]}\n`;
    }).join('');

    // Create canonical request (no query params for CopyObject)
    const canonicalRequest = [
      method,
      url.pathname,
      '', // empty query string
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    // Create string to sign
    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${this.region}/${service}/aws4_request`;
    const canonicalRequestHash = await this.sha256(canonicalRequest);
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      canonicalRequestHash
    ].join('\n');

    // Calculate signature
    const signingKey = await this.getSigningKey(this.credentials.secretKey, dateStamp, this.region, service);
    const signatureBuffer = await this.hmacSha256(signingKey, stringToSign);
    const signature = this.bufferToHex(signatureBuffer);

    // Create authorization header
    const authorization = `${algorithm} Credential=${this.credentials.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // Build final request headers
    const requestHeaders = {
      'Authorization': authorization,
      'X-Amz-Date': amzDate,
      'X-Amz-Content-Sha256': payloadHash,
      'x-amz-copy-source': copySource,
      'x-amz-metadata-directive': 'REPLACE'
    };

    // Add metadata headers
    if (metadata) {
      for (const [metaKey, metaValue] of Object.entries(metadata)) {
        requestHeaders[`x-amz-meta-${metaKey}`] = metaValue;
      }
    }

    // Add content type if specified
    if (contentType) {
      requestHeaders['Content-Type'] = contentType;
    }

    const response = await fetch(url.toString(), {
      method: method,
      headers: requestHeaders
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`HTTP ${response.status}: ${text || response.statusText}`);
    }

    return true;
  }

  /**
   * Escape XML special characters
   */
  escapeXml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  /**
   * Generate an AWS-style access key
   * Format: AKIA + 16 base32-like characters (excluding 0, 1, 8, 9)
   */
  generateAccessKey(prefix = 'AKIA') {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = prefix;
    const randomValues = new Uint8Array(16);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < 16; i++) {
      result += chars[randomValues[i] % chars.length];
    }
    return result;
  }

  /**
   * Generate an AWS-style secret key (40 characters)
   */
  generateSecretKey(length = 40) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let result = '';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < length; i++) {
      result += chars[randomValues[i] % chars.length];
    }
    return result;
  }

  // ============================================
  // Standalone IAM Service (AWS Query protocol)
  // ============================================

  /**
   * Sign a request against the standalone IAM service: signRequest()'s
   * POST/body-hashing branch with a parameterized SigV4 service. Two
   * deliberate differences from the S3/Admin path:
   *   - the signing region is fixed to us-east-1 (iammiddleware.SigningRegion);
   *     the login page's region yields InvalidRegion.
   *   - the body is form-encoded (Action/Version/params), not XML.
   *
   * @param {string} action - IAM or STS action name
   * @param {Object} params - Additional query-protocol parameters
   * @param {string} sigService - 'iam' or 'sts'
   * @returns {Object} - { url, headers, body }
   */
  async signIamRequest(action, params = {}, sigService = 'iam') {
    if (!this.credentials) {
      throw new Error('Not authenticated');
    }
    if (!this.iamEndpoint) {
      throw new Error('IAM API endpoint is not configured');
    }

    const url = new URL(this.iamEndpoint + '/');
    const host = url.host;
    const amzDate = this.getAmzDate();
    const dateStamp = this.getDateStamp();
    const region = IAM_SIGNING_REGION;

    const form = new URLSearchParams();
    form.set('Action', action);
    form.set('Version', sigService === 'sts' ? STS_API_VERSION : IAM_API_VERSION);
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) form.set(key, String(value));
    });
    const body = form.toString();

    const contentType = 'application/x-www-form-urlencoded';
    const payloadHash = await this.sha256(body);

    const headers = {
      'content-type': contentType,
      'host': host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
    };

    const signedHeadersList = Object.keys(headers).sort();
    const signedHeaders = signedHeadersList.join(';');
    const canonicalHeaders = signedHeadersList.map(h => `${h}:${headers[h]}\n`).join('');

    const canonicalRequest = [
      'POST',
      url.pathname,
      '',
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${region}/${sigService}/aws4_request`;
    const canonicalRequestHash = await this.sha256(canonicalRequest);
    const stringToSign = [algorithm, amzDate, credentialScope, canonicalRequestHash].join('\n');

    const signingKey = await this.getSigningKey(this.credentials.secretKey, dateStamp, region, sigService);
    const signatureBuffer = await this.hmacSha256(signingKey, stringToSign);
    const signature = this.bufferToHex(signatureBuffer);

    return {
      url: url.toString(),
      headers: {
        'Authorization': `${algorithm} Credential=${this.credentials.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
        'X-Amz-Date': amzDate,
        'X-Amz-Content-Sha256': payloadHash,
        'Content-Type': contentType,
      },
      body
    };
  }

  /**
   * Make a signed IAM/STS request and parse the XML response
   */
  async iamRequest(action, params = {}, sigService = 'iam') {
    const signed = await this.signIamRequest(action, params, sigService);

    let response;
    try {
      response = await fetch(signed.url, {
        method: 'POST',
        headers: signed.headers,
        body: signed.body,
      });
    } catch (e) {
      if (e instanceof TypeError) {
        throw new Error(`Network error: cannot reach the IAM service. Common causes: CORS policy (the IAM endpoint must allow origin ${window.location.origin}), TLS/certificate error (untrusted or self-signed certificate rejected by the browser), or the service is unreachable.`);
      }
      throw e;
    }

    const responseText = await response.text();

    if (!response.ok) {
      throw new Error(parseXmlErrorMessage(responseText, `HTTP ${response.status}: ${response.statusText}`));
    }

    return this.parseIamResponse(responseText);
  }

  /**
   * Parse an <ActionResponse><ActionResult> envelope into plain JS
   */
  parseIamResponse(xmlString) {
    if (!xmlString || !xmlString.trim()) return {};

    const xmlDoc = new DOMParser().parseFromString(xmlString, 'text/xml');
    if (xmlDoc.querySelector('parsererror')) {
      throw new Error('Invalid XML response from the IAM service');
    }

    const root = xmlDoc.documentElement;
    const result = Array.from(root.children).find(c => /Result$/.test(c.tagName));
    const parsed = this.iamXmlToJs(result || root);
    return (parsed && typeof parsed === 'object') ? parsed : {};
  }

  /**
   * Generic XML -> JS conversion. Any element whose children are all <member>
   * collapses into an array, which is the one list convention this API uses.
   */
  iamXmlToJs(el) {
    const children = Array.from(el.children);
    if (children.length === 0) return el.textContent;
    if (children.every(c => c.tagName === 'member')) {
      return children.map(c => this.iamXmlToJs(c));
    }
    const out = {};
    children.forEach(child => {
      const value = this.iamXmlToJs(child);
      if (child.tagName in out) {
        out[child.tagName] = [].concat(out[child.tagName], value);
      } else {
        out[child.tagName] = value;
      }
    });
    return out;
  }

  /**
   * Decode a percent-encoded policy document (iamutil.EncodePolicyDocument)
   */
  decodePolicyDocument(document) {
    if (typeof document !== 'string' || !document) return document;
    try {
      return decodeURIComponent(document);
    } catch (e) {
      return document;
    }
  }

  /**
   * Write Tags.member.N.Key / Tags.member.N.Value params
   */
  flattenTags(params, tags) {
    (tags || []).forEach((tag, i) => {
      if (!tag || !tag.Key) return;
      params[`Tags.member.${i + 1}.Key`] = tag.Key;
      params[`Tags.member.${i + 1}.Value`] = tag.Value || '';
    });
    return params;
  }

  /**
   * Write <name>.member.N params
   */
  flattenMemberList(params, name, values) {
    (values || []).forEach((value, i) => {
      if (value === undefined || value === null || value === '') return;
      params[`${name}.member.${i + 1}`] = value;
    });
    return params;
  }

  // ---- IAM users ----

  async iamCreateUser(userName, path, tags) {
    const params = { UserName: userName };
    if (path) params.Path = path;
    this.flattenTags(params, tags);
    const result = await this.iamRequest('CreateUser', params);
    return result.User || {};
  }

  async iamGetUser(userName) {
    const params = {};
    if (userName) params.UserName = userName;
    const result = await this.iamRequest('GetUser', params);
    return result.User || {};
  }

  async iamListUsers(options = {}) {
    const params = {};
    if (options.pathPrefix) params.PathPrefix = options.pathPrefix;
    if (options.marker) params.Marker = options.marker;
    if (options.maxItems) params.MaxItems = options.maxItems;
    const result = await this.iamRequest('ListUsers', params);
    return {
      users: iamAsArray(result.Users),
      isTruncated: result.IsTruncated === 'true',
      marker: result.Marker || null
    };
  }

  async iamUpdateUser(userName, newUserName, newPath) {
    const params = { UserName: userName };
    if (newUserName) params.NewUserName = newUserName;
    if (newPath) params.NewPath = newPath;
    const result = await this.iamRequest('UpdateUser', params);
    return result.User || {};
  }

  async iamDeleteUser(userName) {
    await this.iamRequest('DeleteUser', { UserName: userName });
  }

  // ---- User tags ----

  /**
   * Add or replace tags on a user. A key already present is overwritten
   * rather than duplicated, so this doubles as the edit path.
   */
  async iamTagUser(userName, tags) {
    const params = { UserName: userName };
    this.flattenTags(params, tags);
    await this.iamRequest('TagUser', params);
  }

  async iamUntagUser(userName, tagKeys) {
    const params = { UserName: userName };
    this.flattenMemberList(params, 'TagKeys', tagKeys);
    await this.iamRequest('UntagUser', params);
  }

  async iamListUserTags(userName, options = {}) {
    const params = { UserName: userName };
    if (options.marker) params.Marker = options.marker;
    if (options.maxItems) params.MaxItems = options.maxItems;
    const result = await this.iamRequest('ListUserTags', params);
    return {
      tags: iamAsArray(result.Tags),
      isTruncated: result.IsTruncated === 'true',
      marker: result.Marker || null
    };
  }

  // ---- Access keys ----

  /**
   * Create an access key. The server generates both halves of the key pair;
   * the secret is returned here and nowhere else, ever again.
   */
  async iamCreateAccessKey(userName) {
    const result = await this.iamRequest('CreateAccessKey', { UserName: userName });
    return result.AccessKey || {};
  }

  async iamUpdateAccessKey(userName, accessKeyId, status) {
    await this.iamRequest('UpdateAccessKey', { UserName: userName, AccessKeyId: accessKeyId, Status: status });
  }

  async iamDeleteAccessKey(userName, accessKeyId) {
    await this.iamRequest('DeleteAccessKey', { UserName: userName, AccessKeyId: accessKeyId });
  }

  async iamListAccessKeys(userName, options = {}) {
    const params = { UserName: userName };
    if (options.marker) params.Marker = options.marker;
    if (options.maxItems) params.MaxItems = options.maxItems;
    const result = await this.iamRequest('ListAccessKeys', params);
    return {
      keys: iamAsArray(result.AccessKeyMetadata),
      isTruncated: result.IsTruncated === 'true',
      marker: result.Marker || null
    };
  }

  async iamGetAccessKeyLastUsed(accessKeyId) {
    const result = await this.iamRequest('GetAccessKeyLastUsed', { AccessKeyId: accessKeyId });
    return {
      userName: result.UserName || '',
      lastUsed: result.AccessKeyLastUsed || {}
    };
  }

  // ---- User inline policies ----

  async iamPutUserPolicy(userName, policyName, policyDocument) {
    await this.iamRequest('PutUserPolicy', { UserName: userName, PolicyName: policyName, PolicyDocument: policyDocument });
  }

  async iamGetUserPolicy(userName, policyName) {
    const result = await this.iamRequest('GetUserPolicy', { UserName: userName, PolicyName: policyName });
    return {
      userName: result.UserName || userName,
      policyName: result.PolicyName || policyName,
      policyDocument: this.decodePolicyDocument(result.PolicyDocument || '')
    };
  }

  async iamDeleteUserPolicy(userName, policyName) {
    await this.iamRequest('DeleteUserPolicy', { UserName: userName, PolicyName: policyName });
  }

  async iamListUserPolicies(userName, options = {}) {
    const params = { UserName: userName };
    if (options.marker) params.Marker = options.marker;
    if (options.maxItems) params.MaxItems = options.maxItems;
    const result = await this.iamRequest('ListUserPolicies', params);
    return {
      policyNames: iamAsArray(result.PolicyNames),
      isTruncated: result.IsTruncated === 'true',
      marker: result.Marker || null
    };
  }

  // ---- Roles ----

  async iamCreateRole(roleName, assumeRolePolicyDocument, options = {}) {
    const params = { RoleName: roleName, AssumeRolePolicyDocument: assumeRolePolicyDocument };
    if (options.path) params.Path = options.path;
    if (options.description) params.Description = options.description;
    if (options.maxSessionDuration) params.MaxSessionDuration = options.maxSessionDuration;
    this.flattenTags(params, options.tags);
    const result = await this.iamRequest('CreateRole', params);
    return this.decodeRoleTrustPolicy(result.Role || {});
  }

  async iamGetRole(roleName) {
    const result = await this.iamRequest('GetRole', { RoleName: roleName });
    return this.decodeRoleTrustPolicy(result.Role || {});
  }

  async iamListRoles(options = {}) {
    const params = {};
    if (options.pathPrefix) params.PathPrefix = options.pathPrefix;
    if (options.marker) params.Marker = options.marker;
    if (options.maxItems) params.MaxItems = options.maxItems;
    const result = await this.iamRequest('ListRoles', params);
    return {
      roles: iamAsArray(result.Roles).map(role => this.decodeRoleTrustPolicy(role)),
      isTruncated: result.IsTruncated === 'true',
      marker: result.Marker || null
    };
  }

  async iamDeleteRole(roleName) {
    await this.iamRequest('DeleteRole', { RoleName: roleName });
  }

  async iamUpdateAssumeRolePolicy(roleName, policyDocument) {
    await this.iamRequest('UpdateAssumeRolePolicy', { RoleName: roleName, PolicyDocument: policyDocument });
  }

  /**
   * Roles echo their trust policy percent-encoded on create/get/list
   */
  decodeRoleTrustPolicy(role) {
    if (role && role.AssumeRolePolicyDocument) {
      role.AssumeRolePolicyDocument = this.decodePolicyDocument(role.AssumeRolePolicyDocument);
    }
    return role || {};
  }

  // ---- Role inline policies ----

  async iamPutRolePolicy(roleName, policyName, policyDocument) {
    await this.iamRequest('PutRolePolicy', { RoleName: roleName, PolicyName: policyName, PolicyDocument: policyDocument });
  }

  async iamGetRolePolicy(roleName, policyName) {
    const result = await this.iamRequest('GetRolePolicy', { RoleName: roleName, PolicyName: policyName });
    return {
      roleName: result.RoleName || roleName,
      policyName: result.PolicyName || policyName,
      policyDocument: this.decodePolicyDocument(result.PolicyDocument || '')
    };
  }

  async iamDeleteRolePolicy(roleName, policyName) {
    await this.iamRequest('DeleteRolePolicy', { RoleName: roleName, PolicyName: policyName });
  }

  async iamListRolePolicies(roleName, options = {}) {
    const params = { RoleName: roleName };
    if (options.marker) params.Marker = options.marker;
    if (options.maxItems) params.MaxItems = options.maxItems;
    const result = await this.iamRequest('ListRolePolicies', params);
    return {
      policyNames: iamAsArray(result.PolicyNames),
      isTruncated: result.IsTruncated === 'true',
      marker: result.Marker || null
    };
  }

  // ---- OIDC identity providers ----

  async iamCreateOIDCProvider(url, clientIDList, thumbprintList, tags) {
    const params = { Url: url };
    this.flattenMemberList(params, 'ClientIDList', clientIDList);
    this.flattenMemberList(params, 'ThumbprintList', thumbprintList);
    this.flattenTags(params, tags);
    const result = await this.iamRequest('CreateOpenIDConnectProvider', params);
    return {
      arn: result.OpenIDConnectProviderArn || '',
      tags: iamAsArray(result.Tags)
    };
  }

  async iamGetOIDCProvider(arn) {
    const result = await this.iamRequest('GetOpenIDConnectProvider', { OpenIDConnectProviderArn: arn });
    return {
      url: result.Url || '',
      clientIDList: iamAsArray(result.ClientIDList),
      thumbprintList: iamAsArray(result.ThumbprintList),
      createDate: result.CreateDate || '',
      tags: iamAsArray(result.Tags)
    };
  }

  /**
   * List OIDC providers. This action returns ARNs only and has no pagination.
   */
  async iamListOIDCProviders() {
    const result = await this.iamRequest('ListOpenIDConnectProviders', {});
    return iamAsArray(result.OpenIDConnectProviderList)
      .map(entry => (typeof entry === 'string' ? entry : entry.Arn))
      .filter(Boolean);
  }

  async iamDeleteOIDCProvider(arn) {
    await this.iamRequest('DeleteOpenIDConnectProvider', { OpenIDConnectProviderArn: arn });
  }

  async iamAddClientIDToOIDCProvider(arn, clientID) {
    await this.iamRequest('AddClientIDToOpenIDConnectProvider', { OpenIDConnectProviderArn: arn, ClientID: clientID });
  }

  async iamRemoveClientIDFromOIDCProvider(arn, clientID) {
    await this.iamRequest('RemoveClientIDFromOpenIDConnectProvider', { OpenIDConnectProviderArn: arn, ClientID: clientID });
  }

  /**
   * Replace the provider's entire thumbprint list
   */
  async iamUpdateOIDCProviderThumbprint(arn, thumbprintList) {
    const params = { OpenIDConnectProviderArn: arn };
    this.flattenMemberList(params, 'ThumbprintList', thumbprintList);
    await this.iamRequest('UpdateOpenIDConnectProviderThumbprint', params);
  }

  // ---- Self identity (STS) ----

  /**
   * GetCallerIdentity requires no policy grant for any authenticated identity,
   * which makes it both the login-time IAM probe and the "My Identity" source.
   */
  async iamGetCallerIdentity() {
    const result = await this.iamRequest('GetCallerIdentity', {}, 'sts');
    return {
      arn: result.Arn || '',
      userId: result.UserId || '',
      account: result.Account || ''
    };
  }
}

/**
 * URI-encode a string per the AWS SigV4 specification.
 * All characters except the unreserved set (A-Za-z0-9 - _ . ~) are percent-encoded,
 * with hexadecimal digits in uppercase (e.g. %2F, not %2f).
 *
 * @param {string} text - The string to encode.
 * @returns {string} The percent-encoded string.
 */
 function awsUriEncode(text) {
  return encodeURIComponent(text)
    .replace(
      /['()*!]/g,
      (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
    );
}

/**
 * IAM query-protocol constants. The signing region is fixed server-side by
 * iammiddleware.SigningRegion and is deliberately independent of the region
 * chosen on the login page.
 */
const IAM_API_VERSION = '2010-05-08';
const STS_API_VERSION = '2011-06-15';
const IAM_SIGNING_REGION = 'us-east-1';

/**
 * Pull <Code>/<Message> out of an S3, Admin or IAM error body: all three
 * error shapes carry the same two elements.
 *
 * @param {string} responseText - Raw response body
 * @param {string} fallback - Message to use when nothing parses
 * @returns {string} A human-readable error message
 */
function parseXmlErrorMessage(responseText, fallback) {
  try {
    const xmlDoc = new DOMParser().parseFromString(responseText, 'text/xml');
    const code = xmlDoc.querySelector('Code')?.textContent;
    const message = xmlDoc.querySelector('Message')?.textContent;
    if (code) return `${code}: ${message || 'Unknown error'}`;
  } catch (e) {
    // Ignore parsing errors and fall through
  }
  return fallback;
}

/**
 * Normalize a parsed member-list field to an array
 */
function iamAsArray(value) {
  if (value === undefined || value === null || value === '') return [];
  return Array.isArray(value) ? value : [value];
}

// Create global API instance
const api = new VersityAPI();
