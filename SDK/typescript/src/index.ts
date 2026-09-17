/**
 * Authenticity TypeScript SDK — public entry point.
 *
 * Re-exports the client class, all types, and helper constants/functions so a
 * consumer can import everything from a single path:
 *
 *   import { Authenticity, Session, computeHwid } from "authenticity-sdk";
 */

// Re-export the client class and its login-mode constants.
export { Authenticity, LOGIN_TYPE_LICENSE, LOGIN_TYPE_CREDENTIALS } from "./Authenticity";

// Re-export the public data structures.
export type {
  Session,
  AppData,
  Channel,
  Message,
  SavedCredentials,
  UpdateInfo,
} from "./types";

// Re-export HWID generation helpers.
export {
  computeHwid,
  computeHash,
  md5ish,
  HWID_UNKNOWN,
} from "./hwid";

// Re-export the remaining-time breakdown type for advanced consumers.
export type { TimeBreakdown } from "./Authenticity";
