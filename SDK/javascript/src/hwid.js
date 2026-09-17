'use strict';

/**
 * Hardware-ID generation for the Authenticity JavaScript SDK.
 *
 * Produces a stable, deterministic machine fingerprint using the same DJB2
 * algorithm as the C#/C++/Go/Python/Java SDKs so that a given machine yields
 * the same HWID across all implementations within the Authenticity family.
 *
 * This module works in both Node.js and browsers:
 *   - Node: uses os.hostname(), os.platform(), os.arch() and, on Windows,
 *     WMI via PowerShell (best-effort, tolerating failure). On Linux/macOS it
 *     reads /etc/machine-id when readable.
 *   - Browser: best-effort fingerprint built from navigator information.
 *
 * Requirement-free: it uses only global fetch, Node built-ins and the Web
 * Platform APIs that already exist in modern browsers.
 */

// DJB2 constants shared with the other Authenticity SDKs.
const DJB2_SEED = 5381;
const DJB2_XOR_SEED = 0xdeadbeef;
const UNKNOWN_HWID = 'UNKNOWN_HWID';

/**
 * Determine the current runtime environment.
 * @returns {'node'|'browser'|'unknown'}
 */
function detectRuntime() {
  if (typeof process !== 'undefined' && process !== null &&
      typeof process.versions !== 'undefined' && process.versions.node) {
    return 'node';
  }
  if (typeof window !== 'undefined' && typeof navigator !== 'undefined') {
    return 'browser';
  }
  return 'unknown';
}

/**
 * Classic DJB2 hash (seed 5381).
 * @param {string} data
 * @returns {number} the hash as an unsigned 32-bit number.
 */
function djb2(data) {
  let h = DJB2_SEED;
  for (let i = 0; i < data.length; i++) {
    h = (((h << 5) + h) + data.charCodeAt(i)) >>> 0;
  }
  return h >>> 0;
}

/**
 * Second DJB2-XOR variant seeded with 0xDEADBEEF, mirroring the second pass
 * used by the other SDKs.
 * @param {string} data
 * @returns {number} the hash as an unsigned 32-bit number.
 */
function djb2XOR(data) {
  let h = DJB2_XOR_SEED;
  for (let i = 0; i < data.length; i++) {
    h = (((h << 5) + h) + data.charCodeAt(i)) >>> 0;
    h = (h ^ data.charCodeAt(i)) >>> 0;
  }
  return h >>> 0;
}

/**
 * Render a uint32 as an 8-digit lowercase hex string.
 * @param {number} n
 * @returns {string}
 */
function toHex8(n) {
  return ('00000000' + (n >>> 0).toString(16)).slice(-8);
}

/**
 * Read the first non-empty trimmed line of a file (Node only). Returns '' on
 * any failure.
 * @param {string} path
 * @returns {string}
 */
function readFirstLine(path) {
  try {
    // Lazy require so the module is fully usable in browsers where 'fs' is
    // unavailable at load time.
    const fs = require('fs');
    const data = fs.readFileSync(path, 'utf8');
    for (const line of data.split('\n')) {
      const t = line.trim();
      if (t !== '') {
        return t;
      }
    }
  } catch (err) {
    // ignore
  }
  return '';
}

/**
 * Query WMI via PowerShell on Windows (Node only). Best-effort; returns ''
 * on any failure.
 * @param {string} command
 * @returns {string}
 */
function tryWindowsInfo(command) {
  try {
    // Lazy require so the module is usable in browsers.
    const { execFileSync } = require('child_process');
    const args = [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      command,
    ];
    const out = execFileSync('powershell', args, {
      encoding: 'utf8',
      timeout: 10000,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return (out || '').trim().replace(/[\r\n]+/g, '');
  } catch (err) {
    return '';
  }
}


/**
 * Gather stable identifying information about the machine.
 * @returns {string} raw fingerprint string, or '' on total failure.
 */
function machineFingerprint() {
  const parts = [];

  if (detectRuntime() === 'node') {
    try {
      const os = require('os');
      const host = os.hostname();
      if (host) {
        parts.push('host=' + host);
      }
      parts.push('os=' + (os.platform() || ''));
      parts.push('arch=' + (os.arch() || ''));
    } catch (err) {
      // fall through
    }
  } else {
    // Browser best-effort fingerprint.
    if (typeof navigator !== 'undefined') {
      const info = navigator;
      const b = [];
      if (info.userAgent) b.push('ua=' + info.userAgent);
      if (info.platform) b.push('plt=' + info.platform);
      if (info.language) b.push('lang=' + info.language);
      if (info.hardwareConcurrency) b.push('cpu=' + info.hardwareConcurrency);
      if (info.languages && info.languages.length) b.push('langs=' + info.languages.join(','));
      if (b.length) parts.push('browser=' + b.join('&'));
    }
    if (typeof screen !== 'undefined' && screen) {
      parts.push('screen=' + (screen.width || '') + 'x' + (screen.height || ''));
    }
  }

  if (detectRuntime() === 'node') {
    let platform = '';
    try {
      platform = require('os').platform();
    } catch (_e) {
      platform = '';
    }
    if (platform === 'win32' || platform === 'windows') {
      // Try WMI via PowerShell for stable machine identifiers, mirroring the
      // Go / C# / C++ SDKs. Falls back to the MachineGuid registry value.
      let info = tryWindowsInfo(
        "(Get-CimInstance Win32_ComputerSystemProduct).UUID + '|' + (Get-CimInstance Win32_OperatingSystem).SerialNumber"
      );
      if (!info) {
        info = tryWindowsInfo(
          "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid"
        );
      }
      if (info) {
        parts.push('hwid=' + info);
      }
    } else if (platform === 'linux' || platform === 'darwin') {
      const machineId = readFirstLine('/etc/machine-id');
      if (machineId) {
        parts.push('machine=' + machineId);
      }
      if (platform === 'linux') {
        const productId = readFirstLine('/sys/class/dmi/id/product_uuid');
        if (productId) {
          parts.push('product=' + productId);
        }
      }
    }
  }

  if (parts.length < 3) {
    return '';
  }
  return parts.join('|');
}

/**
 * Compute the stable Authenticity hardware ID for this machine.
 * @returns {string} hex HWID string, or 'UNKNOWN_HWID' on total failure.
 */
function computeHwid() {
  const fp = machineFingerprint();
  if (!fp) {
    return UNKNOWN_HWID;
  }
  const h = djb2(fp);
  const h2 = djb2XOR(fp + '|' + h);
  return toHex8(h) + toHex8(h2);
}

/**
 * Compute a secondary machine fingerprint hash using the same algorithm. Used
 * as an additional fingerprint for parity with the other SDKs.
 * @returns {string} hex hash string, or '' on total failure.
 */
function computeHash() {
  const fp = machineFingerprint();
  if (!fp) {
    return '';
  }
  const h = djb2(fp);
  const h2 = djb2XOR(fp + '|' + h);
  return toHex8(h) + toHex8(h2);
}

module.exports = {
  computeHwid,
  computeHash,
  machineFingerprint,
  djb2,
  djb2XOR,
  UNKNOWN_HWID,
};

