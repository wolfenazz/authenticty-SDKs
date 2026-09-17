package com.authenticity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;

/**
 * Generates a stable, per-machine hardware ID consistent with the C#/C++/
 * Python/Go SDKs (DJB2 hashing of machine fingerprints).
 */
final class Hwid {

    private Hwid() {
    }

    /**
     * Generate and return a stable hardware ID for this machine.
     */
    static String generate() {
        try {
            String raw = machineFingerprint();
            if (raw == null || raw.isEmpty()) {
                raw = InetAddress.getLocalHost().getHostName()
                        + System.getProperty("os.name", "")
                        + System.getProperty("os.arch", "");
            }
            long h1 = djb2(raw);
            long h2 = djb2Xor(raw);
            return Long.toHexString(h1).toUpperCase() + Long.toHexString(h2).toUpperCase();
        } catch (Exception e) {
            return "UNKNOWN_HWID";
        }
    }

    private static String machineFingerprint() {
        StringBuilder sb = new StringBuilder();
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            sb.append(wmi("SELECT ProcessorId FROM Win32_Processor", "ProcessorId"));
            sb.append(wmi("SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID = 'C:'",
                    "VolumeSerialNumber"));
            sb.append(System.getProperty("user.name", ""));
            sb.append(wmi("SELECT SerialNumber FROM Win32_BIOS", "SerialNumber"));
        } else {
            sb.append(System.getProperty("user.name", ""));
            sb.append(System.getProperty("os.arch", ""));
        }
        return sb.toString();
    }

    private static String wmi(String query, String field) {
        try {
            Process p = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive",
                    "-Command",
                    "$r = Get-WmiObject -Query \"" + query + "\"; $r." + field)
                    .redirectErrorStream(true)
                    .start();
            StringBuilder out = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    out.append(line.trim());
                }
            }
            p.waitFor();
            return out.toString().trim();
        } catch (Exception e) {
            return "";
        }
    }

    private static long djb2(String data) {
        long hash = 5381;
        for (int i = 0; i < data.length(); i++) {
            hash = ((hash << 5) + hash) + data.charAt(i);
        }
        return hash;
    }

    private static long djb2Xor(String data) {
        long hash = 0xDEADBEEFL;
        for (int i = 0; i < data.length(); i++) {
            hash = ((hash << 5) + hash) ^ data.charAt(i);
        }
        return hash;
    }
}
