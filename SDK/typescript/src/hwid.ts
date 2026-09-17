/**
 * Authenticity TypeScript SDK — HWID (machine fingerprint) generation.
 *
 * Produces a stable, deterministic machine fingerprint derived from the
 * hostname, platform and machine identifiers, hashed with DJB2 (seed 5381)
 * followed by a second DJB2-XOR pass (seed 0xDEADBEEF). This mirrors the C# /
 * C++ / Python / Java / Go SDKs so a given machine yields a consistent HWID
 * across implementations.
 *
 * Generation is best-effort: any total failure yields "UNKNOWN_HWID".
 */

/** Returned by HWID generation on total failure. */
export const HWID_UNKNOWN = "UNKNOWN_HWID";

/** DJB2 seed shared with the other SDKs. */
const DJB2_SEED = 5381;
/** DJB2-XOR seed shared with the other SDKs. */
const DJB2_XOR_SEED = 0xdeadbeef;

/** FNV seed used for the MD5-ish fallback hash. */
const HASH_SEED = 0x811c9dc5;

/** Compute the classic DJB2 hash (seed 5381) of a string, as uint32. */
function djb2(data: string): number {
  let h = DJB2_SEED;
  for (let i = 0; i < data.length; i++) {
    h = ((h << 5) + h + data.charCodeAt(i)) >>> 0;
  }
  return h >>> 0;
}

/**
 * Compute the DJB2-XOR variant (seed 0xDEADBEEF) that also XORs each byte into
 * the hash, mirroring the second pass in the other SDKs.
 */
function djb2XOR(data: string): number {
  let h = DJB2_XOR_SEED >>> 0;
  for (let i = 0; i < data.length; i++) {
    const c = data.charCodeAt(i);
    h = ((((h << 5) + h + c) >>> 0) ^ c) >>> 0;
  }
  return h >>> 0;
}

/** Detect whether the current runtime looks like a browser. */
function isBrowser(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof navigator !== "undefined" &&
    typeof document !== "undefined"
  );
}

/** Try to read the first non-empty line of a file in a Node environment. */
function readFirstLine(path: string): string {
  try {
    // Only available in Node.
    const fs = require("fs") as {
      readFileSync: (p: string, encoding: string) => string;
    };
    const data = fs.readFileSync(path, "utf8");
    for (const line of data.split("\n")) {
      const trimmed = line.trim();
      if (trimmed !== "") {
        return trimmed;
      }
    }
  } catch {
    // ignore — best-effort
  }
  return "";
}

/**
 * Gather stable identifying information about the machine. Any failing source
 * is skipped.
 */
function machineFingerprint(): string {
  const parts: string[] = [];

  if (isBrowser()) {
    // Browser context: best-effort using navigator info.
    const nav = navigator as unknown as Record<string, unknown>;
    const userAgent = typeof nav.userAgent === "string" ? nav.userAgent : "";
    const platform = typeof nav.platform === "string" ? nav.platform : "";
    const lang = typeof nav.language === "string" ? nav.language : "";
    if (userAgent) {
      parts.push("ua=" + userAgent);
    }
    if (platform) {
      parts.push("platform=" + platform);
    }
    if (lang) {
      parts.push("lang=" + lang);
    }
    if (parts.length >= 2) {
      return parts.join("|");
    }
    return "";
  }

  // Node environment.
  let hostname = "";
  let platform = "";
  let arch = "";
  try {
    const os = require("os") as {
      hostname: () => string;
      platform: () => string;
      arch: () => string;
    };
    hostname = os.hostname();
    platform = os.platform();
    arch = os.arch();
  } catch {
    /* ignore */
  }
  if (hostname) {
    parts.push("host=" + hostname);
  }
  if (platform) {
    parts.push("os=" + platform);
  }
  if (arch) {
    parts.push("arch=" + arch);
  }

  if (platform === "win32") {
    const info = tryWindowsInfo();
    if (info) {
      parts.push("hwid=" + info);
    }
  } else if (platform === "linux" || platform === "darwin") {
    const machineId = readFirstLine("/etc/machine-id");
    if (machineId) {
      parts.push("machine=" + machineId);
    }
  }

  if (parts.length < 3) {
    return "";
  }
  return parts.join("|");
}


/**
 * Query stable machine identifiers on Windows via PowerShell, tolerating
 * failure. Mirrors the approach used by the C# / C++ SDKs.
 */
function tryWindowsInfo(): string {
  try {
    const childProcess = require("child_process") as {
      execSync: (cmd: string, opts?: unknown) => Buffer;
    };
    const run = (cmd: string): string => {
      try {
        return childProcess.execSync(cmd, {
          stdio: ["ignore", "pipe", "ignore"],
        }).toString().trim();
      } catch {
        return "";
      }
    };
    let value = run(
      "powershell -NoProfile -NonInteractive -Command \"(Get-CimInstance Win32_ComputerSystemProduct).UUID + '|' + (Get-CimInstance Win32_OperatingSystem).SerialNumber\""
    );
    if (!value) {
      value = run(
        "powershell -NoProfile -NonInteractive -Command \"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid\""
      );
    }
    return value.replace(/[\r\n\s]+/g, "").slice(0, 256);
  } catch {
    return "";
  }
}

/**
 * Compute a stable, deterministic machine fingerprint (HWID). The result is a
 * 32-character lowercase hex string. Returns "UNKNOWN_HWID" on total failure.
 */
export function computeHwid(): string {
  const fp = machineFingerprint();
  if (!fp) {
    return HWID_UNKNOWN;
  }
  const h = djb2(fp);
  const h2 = djb2XOR(fp + "|" + h);
  return padHex(h) + padHex(h2);
}

/**
 * Compute a secondary machine fingerprint hash using the same algorithm. Used
 * as an additional fingerprint for parity with the other SDKs.
 */
export function computeHash(): string {
  const fp = machineFingerprint();
  if (!fp) {
    return "";
  }
  const h = djb2(fp);
  const h2 = djb2XOR(fp + "|" + h);
  return padHex(h) + padHex(h2);
}

/** Left-pad an unsigned 32-bit integer to 8 lowercase hex characters. */
function padHex(value: number): string {
  return (value >>> 0).toString(16).padStart(8, "0");
}

/**
 * Compute a deterministic 8-char hex hash of a string (best-effort MD5-ish).
 * Produces consistent output across runs; usable as a lightweight fingerprint
 * when the Web Crypto API is unavailable.
 */
export function md5ish(input: string): string {
  let h = HASH_SEED >>> 0;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

