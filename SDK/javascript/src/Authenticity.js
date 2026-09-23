'use strict';

/**
 * Authenticity JavaScript SDK
 * ============================
 *
 * A complete, dependency-free (no external packages) client for the
 * Authenticity auth/licensing HTTP API. It mirrors the behavior and feature
 * set of the existing C#/C++/Go/Python/Java SDKs in the same repository.
 *
 * The SDK uses only the global fetch API and Node built-ins, so it runs
 * unmodified in both Node.js (>= 18) and modern browsers (CommonJS module).
 *
 * The base URL provided to the constructor MUST already end with
 * `/api/v1/client` (e.g. `https://your-domain.example/api/v1/client`).
 *
 * All endpoints are POST with `Content-Type: application/json`. Authenticated
 * endpoints send the token as `Authorization: Bearer <token>` AND inside the
 * JSON body. Tolerant parsing handles `success` arriving as a boolean, the
 * string `"true"`/`"false"`, or the number 1/0.
 */

const hwidModule = require('./hwid');

// Login-type constants for auto-login credential persistence (mirrors the Go
// and Python SDKs).
const LoginTypeLicense = 1;
const LoginTypeCredentials = 2;

const LOGIN_JSON_FILE = 'login.json';
const UNKNOWN_HWID = 'UNKNOWN_HWID';
const USER_AGENT = 'Authenticity SDK/1.0 (JavaScript)';

// Endpoint paths, all relative to the base URL which already ends with
// /api/v1/client.
const EP = {
  login: '/auth/login',
  loginUser: '/auth/login-user',
  register: '/auth/register',
  check: '/auth/check',
  checkBlacklist: '/auth/check-blacklist',
  ban: '/auth/ban',
  varsGet: '/vars/get',
  filesDownload: '/files/download',
  webhook: '/webhooks/trigger',
  logsAdd: '/logs/add',
  chatChannels: '/chat/channels',
  chatMessages: '/chat/messages',
  chatProfile: '/chat/profile',
  appUpdate: '/app/update',
};

/**
 * Detect whether code is running in Node.js or a browser.
 * @returns {'node'|'browser'|'unknown'}
 */
function detectRuntime() {
  if (typeof process !== 'undefined' && process !== null &&
      typeof process.versions !== 'undefined' && process.versions.node) {
    return 'node';
  }
  if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined' &&
      typeof navigator !== 'undefined') {
    return 'browser';
  }
  return 'unknown';
}

/**
 * Interpret the server's `success` field tolerantly. The server may return the
 * boolean true/false, the strings "true"/"false" (any casing), or the numbers
 * 1/0. Anything truthy-friendly is treated as success.
 * @param {*} value
 * @returns {boolean}
 */
function asBool(value) {
  if (value === null || value === undefined) {
    return false;
  }
  const t = typeof value;
  if (t === 'boolean') {
    return value;
  }
  if (t === 'number') {
    return value === 1 || value === 1.0;
  }
  if (t === 'string') {
    const s = value.trim().toLowerCase();
    return s === 'true' || s === '1';
  }
  return false;
}

/**
 * Safely stringify a JSON payload, falling back to '{}' on failure.
 * @param {*} obj
 * @returns {string}
 */
function safeStringify(obj) {
  try {
    const s = JSON.stringify(obj);
    return s === undefined ? '{}' : s;
  } catch (err) {
    return '{}';
  }
}

/**
 * Join a relative endpoint onto the client's base URL, ensuring exactly one
 * slash between them.
 * @param {string} baseUrl
 * @param {string} endpoint
 * @returns {string}
 */
function joinUrl(baseUrl, endpoint) {
  let base = baseUrl || '';
  base = base.replace(/\/+$/, '');
  return base + endpoint;
}

/**
 * Normalize a variable/field value to a string for tolerant reads.
 * @param {*} value
 * @returns {string}
 */
function toStr(value) {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return '';
}

/**
 * Convert a value to an integer defensively.
 * @param {*} value
 * @param {number} def
 * @returns {number}
 */
function toInt(value, def) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const n = parseInt(value, 10);
    if (!Number.isNaN(n)) {
      return n;
    }
  }
  return def;
}


/**
 * Return the absolute path to login.json in Node, located next to the current
 * module's directory (commonJS require.context). In a browser this is unused.
 * @returns {string|null}
 */
function credentialsFilePath() {
  if (detectRuntime() !== 'node') {
    return null;
  }
  try {
    const path = require('path');
    // Store next to the SDK module directory for predictability; consumers can
    // override via saveCredentials options if desired.
    return path.join(__dirname, LOGIN_JSON_FILE);
  } catch (err) {
    return null;
  }
}

/**
 * Build a normalized credentials object from raw fields, computing isValid
 * per the shared validation rules (type 1 = license key non-empty; type 2 =
 * username AND password non-empty).
 * @param {number} loginType
 * @param {string} licenseKey
 * @param {string} username
 * @param {string} password
 * @returns {object}
 */
function buildCredentials(loginType, licenseKey, username, password) {
  const creds = {
    loginType: toInt(loginType, 0),
    licenseKey: toStr(licenseKey),
    username: toStr(username),
    password: toStr(password),
    isValid: false,
  };
  if (creds.loginType === LoginTypeLicense) {
    creds.isValid = creds.licenseKey !== '';
  } else if (creds.loginType === LoginTypeCredentials) {
    creds.isValid = creds.username !== '' && creds.password !== '';
  }
  return creds;
}

/**
 * Safely convert an error/unknown value to a message string.
 * @param {*} err
 * @returns {string}
 */
function safeError(err) {
  if (err === null || err === undefined) {
    return 'unknown error';
  }
  if (err instanceof Error) {
    return err.message;
  }
  try {
    return String(err);
  } catch (_e) {
    return 'unknown error';
  }
}

/**
 * Parse an ISO-8601 expiry string (optionally with trailing 'Z') into a Date.
 * Returns null when the value is missing or unparseable. Mirrors the tolerant
 * parsing used across the Authenticity SDKs.
 * @param {*} value
 * @returns {Date|null}
 */
function parseExpiry(value) {
  if (value === null || value === undefined) {
    return null;
  }
  const text = toStr(value).trim();
  if (!text) {
    return null;
  }
  let normalized = text;
  if (normalized.endsWith('Z')) {
    normalized = normalized.slice(0, -1) + '+00:00';
  }
  const t = Date.parse(normalized);
  if (!Number.isNaN(t)) {
    return new Date(t);
  }
  // Manual fallback: strip fraction / trailing timezone.
  let cleaned = text;
  const dot = cleaned.indexOf('.');
  if (dot >= 0) {
    cleaned = cleaned.slice(0, dot);
  }
  cleaned = cleaned.replace('Z', '');
  const t2 = Date.parse(cleaned);
  if (!Number.isNaN(t2)) {
    return new Date(t2);
  }
  return null;
}


/**
 * The main Authenticity client class.
 */
class Authenticity {
  /**
   * Create a new Authenticity client.
   *
   * @param {string} ownerId  Your owner ID from the Authenticity dashboard.
   * @param {string} appId    Your application ID from the dashboard.
   * @param {string} apiUrl   Full API base URL ending with /api/v1/client.
   * @param {string} version  Your application version string.
   * @param {string} licenseKey Optional default license key for license login.
   */
  constructor(ownerId, appId, apiUrl, version, licenseKey) {
    this._ownerId = toStr(ownerId);
    this._appId = toStr(appId);
    // Tolerate a trailing slash but never add one ourselves.
    this._apiUrl = toStr(apiUrl).replace(/\/+$/, '');
    this._version = toStr(version);
    this._licenseKey = toStr(licenseKey);

    this._session = {
      token: '',
      expiry: '',
      username: '',
      ip: '',
      hwid: '',
      level: 0,
      isValid: false,
      updateLink: '',
    };
    this._appData = {
      name: '',
      version: '',
      status: '',
      hwidLock: false,
    };

    this._hwid = hwidModule.computeHwid();
    this._hash = hwidModule.computeHash();
    this._lastError = '';

    this._timeoutMs = 30000;
    this._runtime = detectRuntime();
  }


  // ------------------------------------------------------------------ //
  // Internal HTTP / JSON helpers
  // ------------------------------------------------------------------ //

  /**
   * Set the request timeout (in ms) used for network requests.
   * @param {number} ms
   */
  setRequestTimeout(ms) {
    if (typeof ms === 'number' && ms > 0) {
      this._timeoutMs = ms;
    } else {
      this._timeoutMs = 30000;
    }
  }

  /**
   * Perform a POST request with a JSON body and return the parsed JSON object
   * (or {} on failure). Never throws for business-logic purposes; records the
   * error on the client.
   *
   * @param {string} endpoint Relative endpoint path.
   * @param {object} body     Request body.
   * @param {boolean} authorized Whether to attach the bearer token.
   * @returns {Promise<object>} parsed JSON response.
   */
  async _request(endpoint, body, authorized, method = 'POST') {
    const url = joinUrl(this._apiUrl, endpoint);
    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
    };
    if (authorized && this._session.token) {
      headers['Authorization'] = 'Bearer ' + this._session.token;
    }

    let response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: safeStringify(body || {}),
        signal: this._abortSignal(),
      });
    } catch (err) {
      this._lastError = 'authenticity: network error: ' + safeError(err);
      return {};
    }

    let parsed = {};
    try {
      const text = await response.text();
      if (text && text.trim().length) {
        parsed = JSON.parse(text);
      }
    } catch (err) {
      parsed = {};
    }

    if (!response.ok) {
      const msg = parsed && typeof parsed.message === 'string' && parsed.message
        ? parsed.message
        : 'HTTP status ' + (response.status || '') + ' ' + (response.statusText || '');
      this._lastError = msg;
      return parsed;
    }
    this._lastError = '';
    return parsed;
  }

  /**
   * Build an AbortController signal with the configured timeout, if available.
   * @returns {AbortSignal|undefined}
   */
  _abortSignal() {
    if (typeof AbortController === 'undefined') {
      return undefined;
    }
    try {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), this._timeoutMs);
      if (typeof timer !== 'undefined' && timer && typeof timer.unref === 'function') {
        timer.unref();
      }
      // Note: the timer is intentionally not cleared explicitly; it fires at
      // most once and is harmless if the request completes sooner.
      return ac.signal;
    } catch (err) {
      return undefined;
    }
  }

  /**
   * Perform a GET request and return raw bytes as an ArrayBuffer.
   * @param {string} rawUrl
   * @returns {Promise<ArrayBuffer>}
   */
  async _getBytes(rawUrl) {
    const headers = { 'User-Agent': USER_AGENT };
    let response;
    try {
      response = await fetch(rawUrl, {
        method: 'GET',
        headers,
        signal: this._abortSignal(),
      });
    } catch (err) {
      this._lastError = 'authenticity: download network error: ' + safeError(err);
      throw err;
    }
    if (!response.ok) {
      const msg = 'download returned HTTP ' + (response.statusText || response.status);
      this._lastError = msg;
      throw new Error(msg);
    }
    this._lastError = '';
    return response.arrayBuffer();
  }

  /**
   * True when the session has a token and is marked valid.
   * @returns {boolean}
   */
  _sessionValid() {
    if (!this._session.token || !this._session.isValid) {
      this._lastError = 'authenticity: not logged in or session invalid';
      return false;
    }
    return true;
  }

  // ------------------------------------------------------------------ //
  // Authentication
  // ------------------------------------------------------------------ //

  /**
   * Authenticate using the configured license key.
   * @returns {Promise<boolean>} true on success.
   */
  async login() {
    if (this._licenseKey === '') {
      this._lastError = 'authenticity: license key is empty';
      return false;
    }
    const body = {
      ownerId: this._ownerId,
      appId: this._appId,
      licenseKey: this._licenseKey,
      hwid: this._hwid,
      version: this._version,
      hash: this._hash,
    };
    const resp = await this._request(EP.login, body, false);
    return this._applyLoginResponse(resp);
  }

  /**
   * Authenticate using a username and password.
   * @param {string} username
   * @param {string} password
   * @returns {Promise<boolean>} true on success.
   */
  async loginWithCredentials(username, password) {
    if (toStr(username) === '' || toStr(password) === '') {
      this._lastError = 'authenticity: username and password are required';
      return false;
    }
    const body = {
      ownerId: this._ownerId,
      appId: this._appId,
      username: toStr(username),
      password: toStr(password),
      hwid: this._hwid,
      version: this._version,
      hash: this._hash,
    };
    const resp = await this._request(EP.loginUser, body, false);
    return this._applyLoginResponse(resp);
  }

  /** Check for a server update before login. */
  async checkForUpdate() {
    const resp = await this._request(EP.appUpdate, {
      ownerId: this._ownerId,
      appId: this._appId,
      version: this._version,
    }, false);
    if (!asBool(resp.success)) {
      this._lastError = toStr(resp.message) || 'update check failed';
      return null;
    }
    return {
      updateRequired: asBool(resp.updateRequired),
      clientVersion: toStr(resp.clientVersion) || this._version,
      currentVersion: toStr(resp.currentVersion),
      updateLink: toStr(resp.updateLink),
      appName: toStr(resp.appName),
      appStatus: toStr(resp.appStatus),
    };
  }

  /**
   * Register a new user account with a license key.
   * @param {string} username
   * @param {string} password
   * @param {string} licenseKey
   * @returns {Promise<boolean>} true on success.
   */
  async register(username, password, licenseKey) {
    if (toStr(username) === '' || toStr(password) === '') {
      this._lastError = 'authenticity: username and password are required';
      return false;
    }
    const body = {
      ownerId: this._ownerId,
      appId: this._appId,
      username: toStr(username),
      password: toStr(password),
      licenseKey: licenseKey === undefined ? this._licenseKey : toStr(licenseKey),
      hwid: this._hwid,
      version: this._version,
      hash: this._hash,
    };
    const resp = await this._request(EP.register, body, false);
    const ok = asBool(resp.success);
    if (!ok) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'registration failed';
    }
    return ok;
  }

  /**
   * Extract a successful login response into the session and app data.
   * @param {object} resp
   * @returns {boolean}
   */
  _applyLoginResponse(resp) {
    const ok = asBool(resp.success);
    if (!ok) {
      this._session.updateLink = toStr(resp.updateLink);
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'login failed';
      this._session.isValid = false;
      return false;
    }
    const token = toStr(resp.token);
    if (token === '') {
      this._session.isValid = false;
      this._session.updateLink = toStr(resp.updateLink);
      this._lastError = 'authenticity: login response did not include a session token';
      return false;
    }
    this._session = {
      token,
      expiry: toStr(resp.expiry),
      username: toStr(resp.username),
      ip: toStr(resp.ip),
      hwid: toStr(resp.hwid) || this._hwid,
      level: toInt(resp.level, 0),
      isValid: true,
      updateLink: toStr(resp.updateLink),
    };
    this._appData = {
      name: toStr(resp.appName),
      version: toStr(resp.appVersion),
      status: toStr(resp.appStatus),
      hwidLock: asBool(resp.hwidLock),
    };
    this._lastError = '';
    return true;
  }


  /**
   * Heartbeat / session validation. Returns true while the session is valid.
   * On failure reads expired/reason into lastError and invalidates the session.
   * @returns {Promise<boolean>}
   */
  async checkSession() {
    if (!this._session.isValid || !this._session.token) {
      this._session.isValid = false;
      this._lastError = 'authenticity: not logged in';
      return false;
    }
    const body = { token: this._session.token, appId: this._appId, hwid: this._hwid };
    const resp = await this._request(EP.check, body, true);
    if (asBool(resp.success)) {
      this._session.isValid = true;
      this._lastError = '';
      return true;
    }

    this._session.isValid = false;
    const expired = asBool(resp.expired);
    const reason = toStr(resp.reason) || toStr(resp.message);
    if (expired && reason) {
      this._lastError = 'authenticity: session expired: ' + reason;
    } else if (expired) {
      this._lastError = 'authenticity: session expired';
    } else if (reason) {
      this._lastError = 'authenticity: check failed: ' + reason;
    } else {
      this._lastError = 'authenticity: session check failed';
    }
    return false;
  }

  /**
   * Check whether this machine (HWID) is blacklisted. The server returns
   * success == true when NOT blacklisted; this method therefore returns true
   * when the machine IS blacklisted (mirroring the other SDKs).
   * @returns {Promise<boolean>} true when the machine IS blacklisted.
   */
  async checkBlacklist() {
    const body = {
      ownerId: this._ownerId,
      appId: this._appId,
      hwid: this._hwid,
    };
    const resp = await this._request(EP.checkBlacklist, body, false);
    if (asBool(resp.success)) {
      // success == true means NOT blacklisted.
      this._lastError = '';
      return false;
    }
    this._lastError = typeof resp.message === 'string' && resp.message
      ? resp.message
      : 'hardware is blacklisted';
    return true;
  }

  /**
   * Report abuse and ban the current session. On success the session is
   * invalidated locally.
   * @param {string} reason
   * @returns {Promise<boolean>} true on success.
   */
  async ban(reason) {
    if (!this._session.isValid || !this._session.token) {
      this._lastError = 'authenticity: not logged in';
      return false;
    }
    const body = {
      token: this._session.token,
      appId: this._appId,
      reason: toStr(reason),
    };
    const resp = await this._request(EP.ban, body, true);
    this._session.isValid = false;
    if (!asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'ban request failed';
      return false;
    }
    this._lastError = '';
    return true;
  }

  // ------------------------------------------------------------------ //
  // Remote config / files / webhooks / logs
  // ------------------------------------------------------------------ //

  /**
   * Fetch a remote variable value by name. Returns '' on failure.
   * @param {string} name
   * @returns {Promise<string>}
   */
  async getVariable(name) {
    if (toStr(name) === '') {
      this._lastError = 'authenticity: variable name is required';
      return '';
    }
    if (!this._sessionValid()) {
      return '';
    }
    const body = { token: this._session.token, appId: this._appId, name: toStr(name) };
    const resp = await this._request(EP.varsGet, body, true);
    if (!asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'failed to fetch variable ' + name;
      return '';
    }
    this._lastError = '';
    return toStr(resp.value);
  }

  /**
   * Download a file by ID: resolves the download URL via the API, then GETs the
   * URL to retrieve raw bytes.
   * @param {string} fileId
   * @returns {Promise<ArrayBuffer>} file contents as an ArrayBuffer.
   * @throws when the session is invalid, the URL is empty, or the GET fails.
   */
  async downloadFile(fileId) {
    if (toStr(fileId) === '') {
      this._lastError = 'authenticity: fileId is required';
      throw new Error(this._lastError);
    }
    if (!this._sessionValid()) {
      throw new Error(this._lastError);
    }
    const body = { token: this._session.token, appId: this._appId, fileId: toStr(fileId) };
    const resp = await this._request(EP.filesDownload, body, true);
    if (!asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'failed to fetch download url';
      throw new Error(this._lastError);
    }
    const url = toStr(resp.url) || toStr(resp.downloadUrl);
    if (!url) {
      this._lastError = 'authenticity: file download url is empty';
      throw new Error(this._lastError);
    }
    const data = await this._getBytes(url);
    this._lastError = '';
    return data;
  }

  /**
   * Resolve a file's download URL and open it (best-effort). In a browser this
   * opens the URL in a new tab/window. In Node it prints the URL to stdout.
   * @param {string} fileId
   * @returns {Promise<boolean>} true when the URL was resolved.
   */
  async downloadFileDirect(fileId) {
    if (toStr(fileId) === '') {
      this._lastError = 'authenticity: fileId is required';
      return false;
    }
    if (!this._sessionValid()) {
      return false;
    }
    const body = { token: this._session.token, appId: this._appId, fileId: toStr(fileId) };
    const resp = await this._request(EP.filesDownload, body, true);
    if (!asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'failed to fetch download url';
      return false;
    }
    const url = toStr(resp.url) || toStr(resp.downloadUrl);
    if (!url) {
      this._lastError = 'authenticity: file download url is empty';
      return false;
    }
    if (this._runtime === 'browser') {
      try {
        if (typeof window !== 'undefined' && typeof window.open === 'function') {
          window.open(url, '_blank');
        }
      } catch (err) {
        this._lastError = 'authenticity: failed to open url: ' + safeError(err);
        return false;
      }
    } else {
      // Node: print the URL for the user to open manually.
      try {
        console.log('[Authenticity] Direct download URL: ' + url);
      } catch (err) {
        this._lastError = 'authenticity: failed to print url: ' + safeError(err);
        return false;
      }
    }
    this._lastError = '';
    return true;
  }

  /**
   * Trigger a named webhook with arbitrary data.
   * @param {string} name
   * @param {object} data
   * @returns {Promise<boolean>} true on success.
   */
  async triggerWebhook(name, data) {
    if (toStr(name) === '') {
      this._lastError = 'authenticity: webhook name is required';
      return false;
    }
    if (!this._sessionValid()) {
      return false;
    }
    const body = {
      token: this._session.token,
      appId: this._appId,
      webhookName: toStr(name),
      data: typeof data === 'string' ? data : JSON.stringify(data === null || data === undefined ? {} : data),
    };
    const resp = await this._request(EP.webhook, body, true);
    if (!asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'webhook trigger failed';
      return false;
    }
    this._lastError = '';
    return true;
  }

  /**
   * Send a log entry to the server. Returns a Promise<boolean> so callers can
   * verify the API accepted it.
   * @param {string} data
   * @param {string} type  defaults to "info".
   */
  async log(data, type) {
    if (!this._sessionValid()) {
      return false;
    }
    const logType = toStr(type) === '' ? 'info' : toStr(type);
    const body = {
      token: this._session.token,
      appId: this._appId,
      data: toStr(data),
      type: logType,
    };
    const resp = await this._request(EP.logsAdd, body, true);
    if (!asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'log request failed';
      return false;
    }
    this._lastError = '';
    return true;
  }


  // ------------------------------------------------------------------ //
  // Chat
  // ------------------------------------------------------------------ //

  /**
   * Fetch the list of chat channels. Returns [] on failure.
   * @returns {Promise<Array<{id:string,name:string,cooldownUnit:string,cooldownTime:number}>>}
   */
  async getChannels() {
    if (!this._sessionValid()) {
      return [];
    }
    const body = { token: this._session.token, appId: this._appId };
    const resp = await this._request(EP.chatChannels, body, true);
    const arr = Array.isArray(resp.channels) ? resp.channels : [];
    if (!arr.length && !asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'failed to fetch channels';
      return [];
    }
    const out = arr.map(function (item) {
      if (item === null || typeof item !== 'object') {
        return { id: '', name: '', cooldownUnit: '', cooldownTime: 0 };
      }
      return {
        id: toStr(item.id),
        name: toStr(item.name),
        cooldownUnit: toStr(item.cooldownUnit) || toStr(item.cooldown_unit),
        cooldownTime: toInt(item.cooldownTime, toInt(item.cooldown_time, 0)),
      };
    });
    this._lastError = '';
    return out;
  }

  /**
   * Fetch messages for a channel, or "all" for every channel.
   * @param {string} channelId
   * @returns {Promise<Array<{id:string,channelId:string,senderId:string,sender:string,avatarId:string,content:string,timeSent:string}>>}
   */
  async getMessages(channelId) {
    if (!this._sessionValid()) {
      return [];
    }
    const ch = toStr(channelId) === '' ? 'all' : toStr(channelId);
    const body = { token: this._session.token, appId: this._appId, channelId: ch };
    const resp = await this._request(EP.chatMessages, body, true);
    const arr = Array.isArray(resp.messages) ? resp.messages : [];
    if (!arr.length && !asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'failed to fetch messages';
      return [];
    }
    const out = arr.map(function (item) {
      if (item === null || typeof item !== 'object') {
        return { id: '', channelId: '', senderId: '', sender: '', avatarId: '', content: '', timeSent: '' };
      }
      return {
        id: toStr(item.id),
        channelId: toStr(item.channelId),
        senderId: toStr(item.senderId),
        sender: toStr(item.sender) || toStr(item.author),
        avatarId: toStr(item.avatarId),
        content: toStr(item.content) || toStr(item.text),
        timeSent: toStr(item.timeSent) || toStr(item.timestamp) || toStr(item.time_sent),
      };
    });
    this._lastError = '';
    return out;
  }

  /**
   * Post a message to a channel.
   * @param {string} channelId
   * @param {string} content
   * @returns {Promise<boolean>} true on success.
   */
  async sendMessage(channelId, content) {
    if (toStr(channelId) === '' || toStr(content) === '') {
      this._lastError = 'authenticity: channelId and content are required';
      return false;
    }
    if (!this._sessionValid()) {
      return false;
    }
    const body = {
      token: this._session.token,
      appId: this._appId,
      channelId: toStr(channelId),
      content: toStr(content),
    };
    const resp = await this._request(EP.chatMessages, body, true, 'PUT');
    if (!asBool(resp.success)) {
      this._lastError = typeof resp.message === 'string' && resp.message
        ? resp.message
        : 'failed to send message';
      return false;
    }
    this._lastError = '';
    return true;
  }

  /** @returns {Promise<{id:string,nickname:string,avatarId:string}|null>} */
  async getChatProfile() {
    if (!this._sessionValid()) return null;
    const resp = await this._request(EP.chatProfile,
      { token: this._session.token, appId: this._appId }, true);
    if (!asBool(resp.success)) {
      this._lastError = toStr(resp.message) || 'failed to fetch chat profile';
      return null;
    }
    this._lastError = '';
    return { id: toStr(resp.profileId), nickname: toStr(resp.nickname), avatarId: toStr(resp.avatarId) };
  }

  /** @returns {Promise<{id:string,nickname:string,avatarId:string}|null>} */
  async updateChatProfile(nickname, avatarId) {
    if (!this._sessionValid()) return null;
    const resp = await this._request(EP.chatProfile,
      { token: this._session.token, appId: this._appId, nickname, avatarId }, true, 'PUT');
    if (!asBool(resp.success)) {
      this._lastError = toStr(resp.message) || 'failed to update chat profile';
      return null;
    }
    this._lastError = '';
    return { id: toStr(resp.profileId), nickname: toStr(resp.nickname), avatarId: toStr(resp.avatarId) };
  }

  // ------------------------------------------------------------------ //
  // Getters & helpers
  // ------------------------------------------------------------------ //

  /**
   * Update the client's license key.
   * @param {string} key
   */
  setLicenseKey(key) {
    this._licenseKey = toStr(key);
  }

  /**
   * Return the current session state.
   * @returns {object} {token, expiry, username, ip, hwid, level, isValid, updateLink}
   */
  getSession() {
    return Object.assign({}, this._session);
  }

  /**
   * Return the current application metadata.
   * @returns {object} {name, version, status, hwidLock}
   */
  getAppData() {
    return Object.assign({}, this._appData);
  }

  /**
   * Return the most recent error message, or ''.
   * @returns {string}
   */
  getLastError() {
    return this._lastError;
  }

  /**
   * Return the session update link, if any.
   * @returns {string}
   */
  getUpdateLink() {
    return this._session.updateLink;
  }

  /**
   * Compute a human-readable remaining-time string from the session expiry,
   * e.g. "0 Years : 0 Months : 0 Days : 0 Hours : 5 Mins". Best-effort: if the
   * expiry cannot be parsed an all-zero breakdown is returned.
   * @returns {string}
   */
  getRemainingTime() {
    // Lifetime licenses are returned by the server as the literal "Never".
    if (toStr(this._session.expiry).trim().toLowerCase() === 'never') {
      return 'Lifetime';
    }
    let t = parseExpiry(this._session.expiry);
    if (!t) {
      t = new Date(0);
    }
    const now = Date.now();
    let diff = t.getTime() - now;
    if (diff < 0) {
      return '0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins';
    }

    let years = Math.floor(diff / (365 * 24 * 60 * 60 * 1000));
    diff -= years * 365 * 24 * 60 * 60 * 1000;
    let months = Math.floor(diff / (30 * 24 * 60 * 60 * 1000));
    diff -= months * 30 * 24 * 60 * 60 * 1000;
    let days = Math.floor(diff / (24 * 60 * 60 * 1000));
    diff -= days * 24 * 60 * 60 * 1000;
    let hours = Math.floor(diff / (60 * 60 * 1000));
    diff -= hours * 60 * 60 * 1000;
    let mins = Math.floor(diff / (60 * 1000));

    return years + ' Years : ' + months + ' Months : ' + days + ' Days : ' +
      hours + ' Hours : ' + mins + ' Mins';
  }

  /**
   * Return the generated hardware ID.
   * @returns {string}
   */
  getHwid() {
    return this._hwid;
  }

  /**
   * Return the secondary machine fingerprint hash.
   * @returns {string}
   */
  getHash() {
    return this._hash;
  }

  /**
   * Standalone, static HWID generation convenience wrapper.
   * @returns {string}
   */
  static computeHwid() {
    return hwidModule.computeHwid();
  }

  /**
   * Persist auto-login credentials to disk (Node: login.json next to this SDK
   * module) or localStorage (browser). Returns true on success and records any
   * error on the client.
   *
   * Validation rules (shared across SDKs):
   *   - LoginType 1 (license) is valid when LicenseKey is non-empty.
   *   - LoginType 2 (username/password) is valid when both are non-empty.
   *
   * @param {number} loginType  1 = license key, 2 = username/password.
   * @param {string} licenseKey Used when loginType == 1.
   * @param {string} username   Used when loginType == 2.
   * @param {string} password   Used when loginType == 2.
   * @returns {boolean} true on success.
   */
  saveCredentials(loginType, licenseKey, username, password) {
    const creds = buildCredentials(loginType, licenseKey, username, password);
    const serialized = safeStringify(creds);
    try {
      if (this._runtime === 'browser') {
        if (typeof window !== 'undefined' && window.localStorage) {
          window.localStorage.setItem('authenticity_credentials', serialized);
        }
      } else {
        const fs = require('fs');
        const file = credentialsFilePath();
        if (file) {
          fs.writeFileSync(file, serialized, { mode: 0o600 });
        } else {
          fs.writeFileSync(LOGIN_JSON_FILE, serialized, { mode: 0o600 });
        }
      }
      this._lastError = '';
      return true;
    } catch (err) {
      this._lastError = 'authenticity: failed to save credentials: ' + safeError(err);
      return false;
    }
  }

  /**
   * Read the saved auto-login credentials. If nothing is stored or it cannot be
   * parsed, the returned object has isValid = false.
   * @returns {object} {loginType, licenseKey, username, password, isValid}
   */
  loadCredentials() {
    const notFound = {
      loginType: 0,
      licenseKey: '',
      username: '',
      password: '',
      isValid: false,
    };
    let raw = null;
    try {
      if (this._runtime === 'browser') {
        if (typeof window !== 'undefined' && window.localStorage) {
          raw = window.localStorage.getItem('authenticity_credentials');
        }
      } else {
        const fs = require('fs');
        const file = credentialsFilePath();
        const target = file || LOGIN_JSON_FILE;
        if (fs.existsSync(target)) {
          raw = fs.readFileSync(target, 'utf8');
        }
      }
    } catch (err) {
      this._lastError = '';
      return notFound;
    }
    if (!raw) {
      this._lastError = '';
      return notFound;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      this._lastError = 'authenticity: failed to parse credentials';
      return notFound;
    }
    const creds = {
      loginType: toInt(parsed && parsed.loginType, 0),
      licenseKey: toStr(parsed && parsed.licenseKey),
      username: toStr(parsed && parsed.username),
      password: toStr(parsed && parsed.password),
      isValid: false,
    };
    creds.isValid = buildCredentials(
      creds.loginType,
      creds.licenseKey,
      creds.username,
      creds.password
    ).isValid;
    this._lastError = '';
    return creds;
  }

  /**
   * Remove the saved auto-login credentials. Returns true when removed (or when
   * none were stored).
   * @returns {boolean}
   */
  deleteCredentials() {
    try {
      if (this._runtime === 'browser') {
        if (typeof window !== 'undefined' && window.localStorage) {
          window.localStorage.removeItem('authenticity_credentials');
        }
      } else {
        const fs = require('fs');
        const file = credentialsFilePath();
        const target = file || LOGIN_JSON_FILE;
        if (fs.existsSync(target)) {
          fs.unlinkSync(target);
        }
      }
      this._lastError = '';
      return true;
    } catch (err) {
      this._lastError = 'authenticity: failed to delete credentials: ' + safeError(err);
      return false;
    }
  }
}

module.exports = {
  Authenticity,
  LoginTypeLicense,
  LoginTypeCredentials,
  computeHwid: hwidModule.computeHwid,
  computeHash: hwidModule.computeHash,
};
