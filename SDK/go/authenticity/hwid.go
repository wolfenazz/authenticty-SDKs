package authenticity

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DJB2 constants used to build a stable machine fingerprint hash. These are
// shared with the C#/C++/Python/Java SDKs so that the same machine produces the
// same HWID across all implementations.
const (
	djb2Seed    = 5381
	djb2XORSeed = 0xDEADBEEF
)

// GenerateHwid computes a stable, deterministic machine fingerprint. The result
// is derived from hostname and platform machine information (on Windows, WMI
// via PowerShell is used, like the other SDKs). The raw fingerprint is hashed
// with DJB2 (seed 5381) followed by a second DJB2-XOR pass (seed 0xDEADBEEF),
// then rendered as a hexadecimal string.
//
// This is best-effort: any total failure yields "UNKNOWN_HWID". Callers should
// not depend on the exact format beyond that it is stable for a given machine
// across runs.
func GenerateHwid() string {
	fp := machineFingerprint()
	if fp == "" {
		return hwidUnknown
	}
	h := djb2([]byte(fp))
	h2 := djb2XOR([]byte(fmt.Sprintf("%s|%d", fp, h)))
	return fmt.Sprintf("%016x%016x", h, h2)
}

// GenerateHash produces a secondary machine hash using the same algorithm, used
// as an additional fingerprint for parity with the other SDKs.
func GenerateHash() string {
	fp := machineFingerprint()
	if fp == "" {
		return ""
	}
	h := djb2([]byte(fp))
	h2 := djb2XOR([]byte(fmt.Sprintf("%s|%d", fp, h)))
	return fmt.Sprintf("%016x%016x", h, h2)
}

// djb2 computes the classic DJB2 hash (seed 5381).
func djb2(data []byte) uint64 {
	var h uint64 = djb2Seed
	for _, b := range data {
		h = ((h << 5) + h) + uint64(b) // h*33 + c
	}
	return h
}

// djb2XOR computes a DJB2 variant seeded with 0xDEADBEEF that also XORs each
// byte into the hash, mirroring the second pass in the other SDKs.
func djb2XOR(data []byte) uint64 {
	h := uint64(djb2XORSeed)
	for _, b := range data {
		h = ((h << 5) + h) + uint64(b)
		h ^= uint64(b)
	}
	return h
}

// machineFingerprint gathers stable identifying information about the machine.
// It is deliberately tolerant: any failing source is skipped.
func machineFingerprint() string {
	parts := []string{}
	if host, err := os.Hostname(); err == nil {
		parts = append(parts, "host="+host)
	}
	parts = append(parts, "os="+runtime.GOOS)
	parts = append(parts, "arch="+runtime.GOARCH)

	var info string
	switch runtime.GOOS {
	case "windows":
		info = tryWindowsInfo()
	case "linux":
		info = readFirstLine("/etc/machine-id", "machine=")
	case "darwin":
		info = readFirstLine("/etc/machine-id", "machine=")
	}
	if info != "" {
		parts = append(parts, info)
	}
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts, "|")
}

// readFirstLine returns "prefix"+firstNonEmptyLine of path, or "" on failure.
// It is used for stable machine IDs on Linux/macOS where available.
func readFirstLine(path, prefix string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return prefix + line
		}
	}
	return ""
}

// tryWindowsInfo queries WMI via PowerShell for stable machine identifiers,
// mirroring the approach used by the C#/C++ SDKs.
func tryWindowsInfo() string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-CimInstance Win32_ComputerSystemProduct).UUID + '|' + (Get-CimInstance Win32_OperatingSystem).SerialNumber")
	out, err := cmd.Output()
	if err != nil {
		// Fall back to the machine GUID from the registry via PowerShell.
		cmd2 := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid")
		out, err = cmd2.Output()
		if err != nil {
			return ""
		}
	}
	val := strings.TrimSpace(string(out))
	val = strings.Trim(val, "\r\n")
	val = strings.Trim(val, " ")
	if val == "" {
		return ""
	}
	return "hwid=" + val
}
