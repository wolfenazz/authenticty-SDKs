/**
 * Authenticity TypeScript SDK — shared data structures.
 *
 * These interfaces define the shapes used throughout the SDK and mirror the
 * models exposed by the Go / Python / Java / C# SDKs.
 */

/**
 * Session holds the authentication state established after a successful login.
 */
export interface Session {
  /** The bearer token used to authenticate subsequent requests. */
  token: string;
  /** The human-readable session/license expiry string from the server. */
  expiry: string;
  /** The username of the authenticated user. */
  username: string;
  /** The client IP address reported by the server. */
  ip: string;
  /** The hardware ID reported by the server. */
  hwid: string;
  /** The access level granted by the server. */
  level: number;
  /** True while the session is considered valid. */
  isValid: boolean;
  /** An optional update/download link. Login responses do not include it. */
  updateLink: string;
}

/**
 * AppData holds the application metadata returned by a successful login.
 */
export interface AppData {
  /** The application name. */
  name: string;
  /** The application version. */
  version: string;
  /** The application status string. */
  status: string;
  /** Indicates whether the license is locked to a single machine. */
  hwidLock: boolean;
}

/** Result of a pre-login application version check. */
export interface UpdateInfo {
  updateRequired: boolean;
  clientVersion: string;
  currentVersion: string;
  updateLink: string;
  appName: string;
  appStatus: string;
}

/**
 * Channel describes a chat channel returned by the chats endpoint.
 */
export interface Channel {
  /** The channel identifier. */
  id: string;
  /** The readable channel name. */
  name: string;
  /** The unit used for message cooldown, if any. */
  cooldownUnit: string;
  /** The cooldown duration value. */
  cooldownTime: number;
}

/**
 * Message is a single chat message.
 */
export interface Message {
  /** The message identifier. */
  id: string;
  /** The username of the sender. */
  sender: string;
  /** The message body. */
  content: string;
  /** The timestamp string reported by the server. */
  timeSent: string;
}

/**
 * SavedCredentials is the persisted auto-login entry stored in login.json.
 *
 * LoginType: 1 = license key, 2 = username/password.
 */
export interface SavedCredentials {
  /** The login mode: 1 = license key, 2 = username/password. */
  loginType: number;
  /** Used when LoginType == 1. */
  licenseKey: string;
  /** Used when LoginType == 2. */
  username: string;
  /** Used when LoginType == 2. */
  password: string;
  /** Reports whether the stored set is considered usable. */
  isValid: boolean;
}
