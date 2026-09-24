/**
 * Authenticity TypeScript SDK — client class.
 *
 * A dependency-free (global fetch only) typed client for the Authenticity
 * auth/licensing server. It mirrors the behavior and feature set of the
 * Go / Python / Java / C# SDKs.
 *
 * The provided API URL must already end with "/api/v1/client".
 */

import {
  Session,
  AppData,
  Channel,
  Message,
  ChatProfile,
  SavedCredentials,
  UpdateInfo,
} from "./types";
import { computeHwid, computeHash, md5ish } from "./hwid";

/** HTTP request timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 30000;

/** User-Agent sent with every request. */
const USER_AGENT = "Authenticity SDK/1.0 (TypeScript)";

/** Auto-login mode using a license key. */
export const LOGIN_TYPE_LICENSE = 1;
/** Auto-login mode using username/password. */
export const LOGIN_TYPE_CREDENTIALS = 2;

/** Name of the file holding saved credentials in Node. */
const LOGIN_JSON_FILE = "login.json";

/** Endpoint paths, all relative to the base URL ending in /api/v1/client. */
const ENDPOINT = {
  login: "/auth/login",
  loginUser: "/auth/login-user",
  register: "/auth/register",
  check: "/auth/check",
  checkBlacklist: "/auth/check-blacklist",
  ban: "/auth/ban",
  varsGet: "/vars/get",
  filesDownload: "/files/download",
  webhook: "/webhooks/trigger",
  logsAdd: "/logs/add",
  chatChannels: "/chat/channels",
  chatMessages: "/chat/messages",
  chatProfile: "/chat/profile",
  appUpdate: "/app/update",
} as const;

/** A tolerant wrapper around a decoded JSON response object. */
type JsonRecord = Record<string, unknown>;

/** Detect whether the current runtime looks like a browser. */
function isBrowser(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof navigator !== "undefined" &&
    typeof document !== "undefined"
  );
}

/**
 * Tolerant boolean parsing. The server may return `success` as the string
 * "true"/"false", a real boolean, or the number 1/0. Anything truthy in that
 * sense — "true" (case-insensitive), true, or 1 — reads as success.
 */
function toBool(v: unknown): boolean {
  if (typeof v === "boolean") {
    return v;
  }
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    return s === "true" || s === "1";
  }
  if (typeof v === "number") {
    return v === 1;
  }
  return false;
}

/** Read a string field with a default when missing/unusable. */
function getString(rec: JsonRecord, key: string, def = ""): string {
  const v = rec[key];
  return typeof v === "string" ? v : def;
}

/** Read a boolean field tolerantly with a default. */
function getBool(rec: JsonRecord, key: string, def = false): boolean {
  if (key in rec) {
    return toBool(rec[key]);
  }
  return def;
}

/** Read an integer field with a default when missing/unusable. */
function getInt(rec: JsonRecord, key: string, def = 0): number {
  const v = rec[key];
  if (typeof v === "number") {
    return Math.trunc(v);
  }
  if (typeof v === "string") {
    const n = Number(v);
    if (!Number.isNaN(n)) {
      return Math.trunc(n);
    }
  }
  if (typeof v === "boolean") {
    return v ? 1 : 0;
  }
  return def;
}

/** Read an array field, returning null when missing or not an array. */
function getArray(rec: JsonRecord, key: string): unknown[] | null {
  const v = rec[key];
  return Array.isArray(v) ? v : null;
}

/** A parsed date breakdown used for the human-readable time-remaining string. */
export interface TimeBreakdown {
  years: number;
  months: number;
  days: number;
  hours: number;
  mins: number;
}

/**
 * Best-effort parse of an expiry string into calendar parts. Accepts ISO-8601
 * timestamps, common date formats, and raw millisecond timestamps. Returns
 * all-zeroes on failure or when the expiry is in the past.
 */
function remainingBreakdown(expiry: string): TimeBreakdown {
  const zero: TimeBreakdown = { years: 0, months: 0, days: 0, hours: 0, mins: 0 };
  const exp = (expiry || "").trim();
  if (!exp) {
    return zero;
  }

  let parsed: Date | null = null;

  const iso = new Date(exp);
  if (!Number.isNaN(iso.getTime())) {
    parsed = iso;
  } else {
    // Try a raw millisecond timestamp.
    const ms = Number(exp);
    if (!Number.isNaN(ms) && ms > 0) {
      const d = new Date(ms);
      if (!Number.isNaN(d.getTime())) {
        parsed = d;
      }
    }
  }

  if (!parsed) {
    return zero;
  }

  const now = Date.now();
  if (parsed.getTime() <= now) {
    return zero;
  }

  let diff = parsed.getTime() - now; // milliseconds
  const msPerYear = 365 * 24 * 60 * 60 * 1000;
  const msPerMonth = 30 * 24 * 60 * 60 * 1000;
  const msPerDay = 24 * 60 * 60 * 1000;
  const msPerHour = 60 * 60 * 1000;
  const msPerMin = 60 * 1000;

  const years = Math.floor(diff / msPerYear);
  diff -= years * msPerYear;
  const months = Math.floor(diff / msPerMonth);
  diff -= months * msPerMonth;
  const days = Math.floor(diff / msPerDay);
  diff -= days * msPerDay;
  const hours = Math.floor(diff / msPerHour);
  diff -= hours * msPerHour;
  const mins = Math.floor(diff / msPerMin);

  return { years, months, days, hours, mins };
}

/**
 * Authenticity is the main client. It holds the configuration and live session
 * state and exposes all Authenticity operations. All asynchronous operations
 * use the global fetch API and return Promises.
 */
export class Authenticity {
  /** The Authenticity owner identifier. */
  protected ownerId: string;
  /** The Authenticity application identifier. */
  protected appId: string;
  /** The base URL ending with /api/v1/client. */
  protected apiUrl: string;
  /** The SDK/client version reported to the server. */
  protected version: string;
  /** The license key used for license-key based login. */
  protected licenseKey: string;
  /** The generated hardware ID of this machine. */
  protected hwid: string;
  /** A secondary machine fingerprint hash. */
  protected hash: string;
  /** The current authentication session. */
  protected session: Session;
  /** The application metadata from the last login. */
  protected appData: AppData;
  /** The most recent error message, if any. */
  protected lastError: string;

  /**
   * Create an Authenticity client.
   *
   * @param ownerId the Authenticity owner identifier
   * @param appId the Authenticity application identifier
   * @param apiUrl the base URL, which must already end with "/api/v1/client"
   * @param version the client/application version reported to the server
   * @param licenseKey optional license key for license-key login
   */
  constructor(
    ownerId: string,
    appId: string,
    apiUrl: string,
    version: string,
    licenseKey = ""
  ) {
    this.ownerId = ownerId;
    this.appId = appId;
    this.apiUrl = apiUrl;
    this.version = version;
    this.licenseKey = licenseKey;
    this.hwid = computeHwid();
    this.hash = computeHash() || md5ish(licenseKey + appId + ownerId);
    this.session = {
      token: "",
      expiry: "",
      username: "",
      ip: "",
      hwid: "",
      level: 0,
      subscriptionId: null,
      subscriptionName: null,
      features: [],
      limits: {},
      isValid: false,
      updateLink: "",
    };
    this.appData = { name: "", version: "", status: "", hwidLock: false };
    this.lastError = "";
  }


  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /** Record the most recent error message on this client. */
  protected setErr(msg: string): void {
    this.lastError = msg;
  }

  /** Report whether a token exists and the session is marked valid. */
  protected sessionValid(): boolean {
    if (!this.session.token || !this.session.isValid) {
      this.setErr("authenticity: not logged in or session invalid");
      return false;
    }
    return true;
  }

  /** Join a relative endpoint onto the base URL, ensuring a single slash. */
  protected makeUrl(endpoint: string): string {
    const base = this.apiUrl || "";
    return base.replace(/\/+$/, "") + endpoint;
  }

  /**
   * Perform a POST request with a JSON body and return the decoded JSON
   * response (tolerantly parsed). Non-2xx statuses surface the server message
   * on lastError but still return the parsed body so business fields can be
   * extracted.
   */
  protected async request(
    endpoint: string,
    body: Record<string, unknown>,
    authorized: boolean,
    method = "POST"
  ): Promise<JsonRecord> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      };
      if (authorized && this.session.token) {
        headers["Authorization"] = "Bearer " + this.session.token;
      }

      const resp = await fetch(this.makeUrl(endpoint), {
        method,
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      let parsed: JsonRecord = {};
      try {
        parsed = (await resp.json()) as JsonRecord;
      } catch {
        parsed = {};
      }

      if (!resp.ok) {
        const msg =
          getString(parsed, "message", "") ||
          "HTTP status " + resp.status + " " + resp.statusText;
        this.setErr(msg);
        return parsed;
      }

      this.setErr("");
      return parsed;
    } catch (err) {
      const msg =
        err instanceof Error ? err.message : String(err);
      this.setErr("authenticity: network error: " + msg);
      return {};
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Perform a plain GET request (used for file downloads) and return the raw
   * bytes as an ArrayBuffer. Follows redirects automatically.
   */
  protected async getBytes(rawUrl: string): Promise<ArrayBuffer | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const headers: Record<string, string> = { "User-Agent": USER_AGENT };
      const resp = await fetch(rawUrl, { method: "GET", headers, signal: controller.signal });
      if (!resp.ok) {
        this.setErr("download returned HTTP " + resp.status + " " + resp.statusText);
        return null;
      }
      this.setErr("");
      return await resp.arrayBuffer();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.setErr("authenticity: download network error: " + msg);
      return null;
    } finally {
      clearTimeout(timer);
    }
  }


  // ---------------------------------------------------------------------------
  // Authentication
  // ---------------------------------------------------------------------------

  /**
   * Extract a login response into the client's Session and AppData. The
   * updateLink field is tolerant of the server not sending it.
   */
  protected applyLoginResponse(resp: JsonRecord): boolean {
    const ok = getBool(resp, "success", false);
    if (!ok) {
      const msg = getString(resp, "message", "login failed");
      this.session.updateLink = getString(resp, "updateLink", "");
      this.setErr(msg);
      this.session.isValid = false;
      return false;
    }

    const token = getString(resp, "token", "");
    if (!token) {
      this.session.isValid = false;
      this.session.updateLink = getString(resp, "updateLink", "");
      this.setErr("authenticity: login response did not include a session token");
      return false;
    }

    this.session = {
      token,
      expiry: getString(resp, "expiry", ""),
      username: getString(resp, "username", ""),
      ip: getString(resp, "ip", ""),
      hwid: getString(resp, "hwid", this.hwid),
      level: getInt(resp, "level", 0),
      subscriptionId: getString(resp, "subscriptionId") || null,
      subscriptionName: getString(resp, "subscriptionName") || null,
      features: (getArray(resp, "features") || []).filter((v): v is string => typeof v === "string"),
      limits: Object.fromEntries(Object.entries((resp.limits && typeof resp.limits === "object" ? resp.limits : {}) as Record<string, unknown>)
        .filter((entry): entry is [string, number] => typeof entry[1] === "number" && Number.isFinite(entry[1]) && entry[1] >= 0)),
      isValid: true,
      updateLink: getString(resp, "updateLink", ""),
    };
    this.appData = {
      name: getString(resp, "appName", ""),
      version: getString(resp, "appVersion", ""),
      status: getString(resp, "appStatus", ""),
      hwidLock: getBool(resp, "hwidLock", false),
    };
    this.setErr("");
    return true;
  }

  /**
   * Authenticate using the configured license key. Returns true on success and
   * populates the session and app data.
   */
  async login(): Promise<boolean> {
    if (!this.licenseKey) {
      this.setErr("authenticity: license key is empty");
      return false;
    }
    const body: Record<string, unknown> = {
      ownerId: this.ownerId,
      appId: this.appId,
      licenseKey: this.licenseKey,
      hwid: this.hwid,
      version: this.version,
      hash: this.hash,
    };
    const resp = await this.request(ENDPOINT.login, body, false);
    return this.applyLoginResponse(resp);
  }

  /**
   * Authenticate a username/password pair against the server.
   */
  async loginWithCredentials(username: string, password: string): Promise<boolean> {
    if (!username || !password) {
      this.setErr("authenticity: username and password are required");
      return false;
    }
    const body: Record<string, unknown> = {
      ownerId: this.ownerId,
      appId: this.appId,
      username,
      password,
      hwid: this.hwid,
      version: this.version,
      hash: this.hash,
    };
    const resp = await this.request(ENDPOINT.loginUser, body, false);
    return this.applyLoginResponse(resp);
  }

  /** Check for a server update before login. */
  async checkForUpdate(): Promise<UpdateInfo | null> {
    const resp = await this.request(ENDPOINT.appUpdate, {
      ownerId: this.ownerId,
      appId: this.appId,
      version: this.version,
    }, false);
    if (!getBool(resp, "success", false)) {
      this.setErr(getString(resp, "message", "update check failed"));
      return null;
    }
    return {
      updateRequired: getBool(resp, "updateRequired", false),
      clientVersion: getString(resp, "clientVersion", this.version),
      currentVersion: getString(resp, "currentVersion", ""),
      updateLink: getString(resp, "updateLink", ""),
      appName: getString(resp, "appName", ""),
      appStatus: getString(resp, "appStatus", ""),
    };
  }

  /**
   * Create a new user account. Returns true only when the server responds with
   * success == true.
   */
  async register(username: string, password: string, licenseKey: string): Promise<boolean> {
    if (!username || !password) {
      this.setErr("authenticity: username and password are required");
      return false;
    }
    const body: Record<string, unknown> = {
      ownerId: this.ownerId,
      appId: this.appId,
      username,
      password,
      licenseKey,
      hwid: this.hwid,
      version: this.version,
      hash: this.hash,
    };
    const resp = await this.request(ENDPOINT.register, body, false);
    const ok = getBool(resp, "success", false);
    if (!ok) {
      this.setErr(getString(resp, "message", "registration failed"));
    }
    return ok;
  }

  /**
   * Perform a heartbeat against /auth/check. Returns true while the session is
   * valid. On failure reads expired/reason into lastError and invalidates the
   * session.
   */
  async checkSession(): Promise<boolean> {
    if (!this.session.isValid || !this.session.token) {
      this.session.isValid = false;
      this.setErr("authenticity: not logged in");
      return false;
    }
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      hwid: this.hwid,
    };
    const resp = await this.request(ENDPOINT.check, body, true);
    const ok = getBool(resp, "success", false);
    if (ok) {
      this.session.isValid = true;
      this.applySubscriptionFields(resp);
      this.setErr("");
      return true;
    }

    this.session.isValid = false;
    const expired = getBool(resp, "expired", false);
    const reason = getString(resp, "reason", getString(resp, "message", ""));
    if (expired && reason) {
      this.setErr("authenticity: session expired: " + reason);
    } else if (expired) {
      this.setErr("authenticity: session expired");
    } else if (reason) {
      this.setErr("authenticity: check failed: " + reason);
    } else {
      this.setErr("authenticity: session check failed");
    }
    return false;
  }

  /** Refresh subscription entitlements from an auth/check response. */
  private applySubscriptionFields(resp: JsonRecord): void {
    if ("subscriptionId" in resp) this.session.subscriptionId = getString(resp, "subscriptionId") || null;
    if ("subscriptionName" in resp) this.session.subscriptionName = getString(resp, "subscriptionName") || null;
    if ("level" in resp) this.session.level = getInt(resp, "level", this.session.level);
    if ("features" in resp) this.session.features = (getArray(resp, "features") || []).filter((v): v is string => typeof v === "string");
    if (resp.limits && typeof resp.limits === "object") {
      this.session.limits = Object.fromEntries(Object.entries(resp.limits as Record<string, unknown>)
        .filter((entry): entry is [string, number] => typeof entry[1] === "number" && Number.isFinite(entry[1]) && entry[1] >= 0));
    }
  }

  /** Ask the server whether the active subscription grants a feature. */
  async hasFeature(feature: string): Promise<boolean> {
    if (!feature || !this.session.isValid || !this.session.token) return false;
    const resp = await this.request(ENDPOINT.check, {
      token: this.session.token, appId: this.appId, hwid: this.hwid, feature,
    }, true);
    const allowed = getBool(resp, "success", false);
    if (allowed) this.applySubscriptionFields(resp);
    return allowed;
  }

  /**
   * Check whether the current hardware is blacklisted. The server returns
   * success == true when the HWID is NOT blacklisted, so this method returns
   * true when the machine IS blacklisted (mirroring the other SDKs).
   */
  async checkBlacklist(): Promise<boolean> {
    const body: Record<string, unknown> = {
      ownerId: this.ownerId,
      appId: this.appId,
      hwid: this.hwid,
    };
    const resp = await this.request(ENDPOINT.checkBlacklist, body, false);
    const ok = getBool(resp, "success", false);
    if (ok) {
      // success == true means NOT blacklisted.
      this.setErr("");
      return false;
    }
    this.setErr(getString(resp, "message", "hardware is blacklisted"));
    return true;
  }

  /**
   * Revoke the current session by reporting an abuse reason to the server. On
   * success the local session is invalidated. Returns true on success.
   */
  async ban(reason: string): Promise<boolean> {
    if (!this.session.isValid || !this.session.token) {
      this.setErr("authenticity: not logged in");
      return false;
    }
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      reason,
    };
    const resp = await this.request(ENDPOINT.ban, body, true);
    const ok = getBool(resp, "success", false);
    this.session.isValid = false;
    if (!ok) {
      this.setErr(getString(resp, "message", "ban request failed"));
      return false;
    }
    this.setErr("");
    return true;
  }


  // ---------------------------------------------------------------------------
  // Features & Data
  // ---------------------------------------------------------------------------

  /**
   * Fetch the value of a server-side variable. Returns the value or an empty
   * string on failure (recording the error on the client).
   */
  async getVariable(name: string): Promise<string> {
    if (!name) {
      this.setErr("authenticity: variable name is required");
      return "";
    }
    if (!this.sessionValid()) {
      return "";
    }
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      name,
    };
    const resp = await this.request(ENDPOINT.varsGet, body, true);
    if (!getBool(resp, "success", false)) {
      this.setErr(getString(resp, "message", "failed to fetch variable " + name));
      return "";
    }
    this.setErr("");
    return getString(resp, "value", "");
  }

  /**
   * Resolve a file's download URL from the server, then perform a separate GET
   * to retrieve the raw bytes. Returns the file contents as an ArrayBuffer.
   */
  async downloadFile(fileId: string): Promise<ArrayBuffer> {
    const empty = new ArrayBuffer(0);
    if (!fileId) {
      this.setErr("authenticity: fileId is required");
      return empty;
    }
    if (!this.sessionValid()) {
      return empty;
    }
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      fileId,
    };
    const resp = await this.request(ENDPOINT.filesDownload, body, true);
    if (!getBool(resp, "success", false)) {
      this.setErr(getString(resp, "message", "failed to fetch download url"));
      return empty;
    }
    const url = getString(resp, "url", getString(resp, "downloadUrl", ""));
    if (!url) {
      this.setErr("authenticity: file download url is empty");
      return empty;
    }
    const bytes = await this.getBytes(url);
    if (bytes === null) {
      return empty;
    }
    return bytes;
  }

  /**
   * Resolve a file's download URL and open it in the user's browser (or print
   * the URL in a Node environment). Best-effort; returns true when invoked.
   */
  async downloadFileDirect(fileId: string): Promise<boolean> {
    if (!fileId) {
      this.setErr("authenticity: fileId is required");
      return false;
    }
    if (!this.sessionValid()) {
      return false;
    }
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      fileId,
    };
    const resp = await this.request(ENDPOINT.filesDownload, body, true);
    if (!getBool(resp, "success", false)) {
      this.setErr(getString(resp, "message", "failed to fetch download url"));
      return false;
    }
    const url = getString(resp, "url", getString(resp, "downloadUrl", ""));
    if (!url) {
      this.setErr("authenticity: file download url is empty");
      return false;
    }
    try {
      if (isBrowser()) {
        window.open(url, "_blank");
      } else {
        console.log("Authenticity download URL: " + url);
      }
      this.setErr("");
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.setErr("authenticity: failed to open url: " + msg);
      return false;
    }
  }

  /**
   * Fire a named webhook with arbitrary data on the server. Returns true when
   * the server acknowledges success.
   */
  async triggerWebhook(name: string, data: unknown): Promise<boolean> {
    if (!name) {
      this.setErr("authenticity: webhook name is required");
      return false;
    }
    if (!this.sessionValid()) {
      return false;
    }
    const webhookData = typeof data === "string" ? data : JSON.stringify(data ?? {});
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      webhookName: name,
      data: webhookData,
    };
    const resp = await this.request(ENDPOINT.webhook, body, true);
    const ok = getBool(resp, "success", false);
    if (!ok) {
      this.setErr(getString(resp, "message", "webhook trigger failed"));
      return false;
    }
    this.setErr("");
    return true;
  }

  /**
   * Send a log entry to the server. Returns false without a valid session or
   * when the API rejects the request.
   */
  async log(data: unknown, type: string): Promise<boolean> {
    if (!this.sessionValid()) {
      return false;
    }
    const logType = type || "info";
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      data: typeof data === "string" ? data : JSON.stringify(data ?? {}),
      type: logType,
    };
    const resp = await this.request(ENDPOINT.logsAdd, body, true);
    const ok = getBool(resp, "success", false);
    if (!ok) {
      this.setErr(getString(resp, "message", "log request failed"));
      return false;
    }
    this.setErr("");
    return true;
  }


  /**
   * Fetch the list of available chat channels. Returns an empty array on
   * failure.
   */
  async getChannels(): Promise<Channel[]> {
    if (!this.sessionValid()) {
      return [];
    }
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
    };
    const resp = await this.request(ENDPOINT.chatChannels, body, true);
    const arr = getArray(resp, "channels");
    if (!arr) {
      this.setErr(getString(resp, "message", "failed to fetch channels"));
      return [];
    }
    const out: Channel[] = [];
    for (const item of arr) {
      if (typeof item !== "object" || item === null) {
        continue;
      }
      const rec = item as Record<string, unknown>;
      out.push({
        id: getString(rec, "id", ""),
        name: getString(rec, "name", ""),
        cooldownUnit: getString(rec, "cooldownUnit", getString(rec, "cooldown_unit", "")),
        cooldownTime: getInt(rec, "cooldownTime", getInt(rec, "cooldown_time", 0)),
      });
    }
    this.setErr("");
    return out;
  }

  /**
   * Fetch messages for a channel ("all" fetches messages from all channels).
   * Returns an empty array on failure.
   */
  async getMessages(channelId: string): Promise<Message[]> {
    if (!this.sessionValid()) {
      return [];
    }
    const id = channelId || "all";
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      channelId: id,
    };
    const resp = await this.request(ENDPOINT.chatMessages, body, true);
    const arr = getArray(resp, "messages");
    if (!arr) {
      this.setErr(getString(resp, "message", "failed to fetch messages"));
      return [];
    }
    const out: Message[] = [];
    for (const item of arr) {
      if (typeof item !== "object" || item === null) {
        continue;
      }
      const rec = item as Record<string, unknown>;
      out.push({
        id: getString(rec, "id", ""),
        channelId: getString(rec, "channelId", ""),
        senderId: getString(rec, "senderId", ""),
        sender: getString(rec, "sender", getString(rec, "author", "")),
        avatarId: getString(rec, "avatarId", ""),
        content: getString(rec, "content", getString(rec, "text", "")),
        timeSent: getString(
          rec,
          "timeSent",
          getString(rec, "timestamp", getString(rec, "time_sent", ""))
        ),
      });
    }
    this.setErr("");
    return out;
  }

  /**
   * Post a new message to a channel. Returns true on success.
   */
  async sendMessage(channelId: string, content: string): Promise<boolean> {
    if (!channelId || !content) {
      this.setErr("authenticity: channelId and content are required");
      return false;
    }
    if (!this.sessionValid()) {
      return false;
    }
    const body: Record<string, unknown> = {
      token: this.session.token,
      appId: this.appId,
      channelId,
      content,
    };
    const resp = await this.request(ENDPOINT.chatMessages, body, true, "PUT");
    const ok = getBool(resp, "success", false);
    if (!ok) {
      this.setErr(getString(resp, "message", "failed to send message"));
      return false;
    }
    this.setErr("");
    return true;
  }

  /** Read the current user's chat nickname and avatar. */
  async getChatProfile(): Promise<ChatProfile | null> {
    if (!this.sessionValid()) return null;
    const resp = await this.request(ENDPOINT.chatProfile, {
      token: this.session.token, appId: this.appId,
    }, true);
    if (!getBool(resp, "success")) {
      this.setErr(getString(resp, "message", "failed to fetch chat profile"));
      return null;
    }
    this.setErr("");
    return {
      id: getString(resp, "profileId"),
      nickname: getString(resp, "nickname"),
      avatarId: getString(resp, "avatarId"),
    };
  }

  /** Update the current user's chat nickname and application avatar ID. */
  async updateChatProfile(nickname: string, avatarId: string): Promise<ChatProfile | null> {
    if (!this.sessionValid()) return null;
    const resp = await this.request(ENDPOINT.chatProfile, {
      token: this.session.token, appId: this.appId, nickname, avatarId,
    }, true, "PUT");
    if (!getBool(resp, "success")) {
      this.setErr(getString(resp, "message", "failed to update chat profile"));
      return null;
    }
    this.setErr("");
    return {
      id: getString(resp, "profileId"),
      nickname: getString(resp, "nickname"),
      avatarId: getString(resp, "avatarId"),
    };
  }


  // ---------------------------------------------------------------------------
  // Getters & helpers
  // ---------------------------------------------------------------------------

  /** Update the client's license key. */
  setLicenseKey(key: string): void {
    this.licenseKey = key;
  }

  /** Return a copy of the current session state. */
  getSession(): Session {
    return { ...this.session };
  }

  /** Return a copy of the current application metadata. */
  getAppData(): AppData {
    return { ...this.appData };
  }

  /** Return the most recent error message, or an empty string. */
  getLastError(): string {
    return this.lastError;
  }

  /**
   * Return the update link from the session. Login responses do not include an
   * update link, so this typically returns an empty string (retained for
   * parity with the other SDKs).
   */
  getUpdateLink(): string {
    return this.session.updateLink;
  }

  /** Return the generated hardware ID of this machine. */
  getHwid(): string {
    return this.hwid;
  }

  /** Return the secondary machine fingerprint hash. */
  getHash(): string {
    return this.hash;
  }

  /**
   * Compute a human-readable remaining-time string from the session expiry in
   * the format used by the other SDKs:
   *
   *   "X Years : X Months : X Days : X Hours : X Mins"
   *
   * The server expiry string is parsed leniently; if it cannot be interpreted
   * or is in the past, an all-zero breakdown is returned.
   */
  getRemainingTime(): string {
    // Lifetime licenses are returned by the server as the literal "Never".
    if (this.session.expiry.trim().toLowerCase() === "never") {
      return "Lifetime";
    }
    const b = remainingBreakdown(this.session.expiry);
    return (
      b.years +
      " Years : " +
      b.months +
      " Months : " +
      b.days +
      " Days : " +
      b.hours +
      " Hours : " +
      b.mins +
      " Mins"
    );
  }

  /** Standalone HWID generation, as a convenience static. */
  static computeHwid(): string {
    return computeHwid();
  }


  // ---------------------------------------------------------------------------
  // Auto-login credentials
  // ---------------------------------------------------------------------------

  /**
   * Persist the auto-login information. In Node this writes "login.json" in the
   * current working directory; in a browser it uses localStorage. Best-effort.
   *
   * Validation rules (shared across SDKs):
   *   - LoginType 1 (license) is valid when LicenseKey is non-empty.
   *   - LoginType 2 (username/password) is valid when both are non-empty.
   *
   * The raw values are still written so they are preserved; the isValid flag
   * reflects the validation outcome.
   */
  saveCredentials(
    loginType: number,
    licenseKey: string,
    username: string,
    password: string
  ): boolean {
    const creds: SavedCredentials = {
      loginType,
      licenseKey,
      username,
      password,
      isValid: credentialsValid(loginType, licenseKey, username, password),
    };
    const serialized = JSON.stringify(creds, null, 2);
    try {
      if (isBrowser()) {
        window.localStorage.setItem("authenticity_credentials", serialized);
      } else {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const fs = require("fs") as { writeFileSync: (p: string, d: string, o?: object) => void };
        fs.writeFileSync(LOGIN_JSON_FILE, serialized, { mode: 0o600 });
      }
      this.setErr("");
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.setErr("authenticity: failed to save credentials: " + msg);
      return false;
    }
  }

  /**
   * Read the saved auto-login credentials. If nothing is stored or it cannot be
   * read, the returned credentials have isValid = false.
   */
  loadCredentials(): SavedCredentials {
    const notFound: SavedCredentials = {
      loginType: 0,
      licenseKey: "",
      username: "",
      password: "",
      isValid: false,
    };
    let raw: string | null = null;
    try {
      if (isBrowser()) {
        raw = window.localStorage.getItem("authenticity_credentials");
      } else {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const fs = require("fs") as { readFileSync: (p: string, e: string) => string };
        raw = fs.readFileSync(LOGIN_JSON_FILE, "utf8");
      }
    } catch {
      this.setErr("");
      return notFound;
    }
    if (!raw) {
      this.setErr("");
      return notFound;
    }
    try {
      const parsed = JSON.parse(raw) as Partial<SavedCredentials>;
      const creds: SavedCredentials = {
        loginType: typeof parsed.loginType === "number" ? parsed.loginType : 0,
        licenseKey: typeof parsed.licenseKey === "string" ? parsed.licenseKey : "",
        username: typeof parsed.username === "string" ? parsed.username : "",
        password: typeof parsed.password === "string" ? parsed.password : "",
        isValid: false,
      };
      creds.isValid = credentialsValid(
        creds.loginType,
        creds.licenseKey,
        creds.username,
        creds.password
      );
      this.setErr("");
      return creds;
    } catch {
      this.setErr("authenticity: failed to parse credentials");
      return notFound;
    }
  }

  /**
   * Delete the saved auto-login credentials. Returns true when the credentials
   * were removed (or did not exist).
   */
  deleteCredentials(): boolean {
    try {
      if (isBrowser()) {
        window.localStorage.removeItem("authenticity_credentials");
      } else {
        const fs = require("fs") as { existsSync: (p: string) => boolean; unlinkSync: (p: string) => void };
        if (fs.existsSync(LOGIN_JSON_FILE)) {
          fs.unlinkSync(LOGIN_JSON_FILE);
        }
      }
      this.setErr("");
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.setErr("authenticity: failed to delete credentials: " + msg);
      return false;
    }
  }
}

/**
 * Implement the shared auto-login validation rules.
 *   - LoginType 1 (license) is valid when LicenseKey is non-empty.
 *   - LoginType 2 (username/password) is valid when both are non-empty.
 */
function credentialsValid(
  loginType: number,
  licenseKey: string,
  username: string,
  password: string
): boolean {
  switch (loginType) {
    case LOGIN_TYPE_LICENSE:
      return !!licenseKey;
    case LOGIN_TYPE_CREDENTIALS:
      return !!username && !!password;
    default:
      return false;
  }
}
