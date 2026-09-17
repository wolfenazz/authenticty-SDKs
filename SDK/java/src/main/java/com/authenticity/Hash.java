package com.authenticity;

import java.io.InputStream;
import java.security.MessageDigest;

/**
 * Computes an MD5 hash of the running application code as an integrity check,
 * matching the behaviour of the other Authenticity SDKs.
 */
final class Hash {

    private Hash() {
    }

    /**
     * Hash the running code (class resource or code source location) with MD5.
     *
     * @return lowercase hex MD5, or empty string on failure
     */
    static String hashExecutable() {
        try {
            String location = Authenticity.class.getProtectionDomain()
                    .getCodeSource().getLocation().getPath();
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            try (InputStream in = new java.io.FileInputStream(
                    new java.io.File(java.net.URI.create("file:" + location)))) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    md5.update(buffer, 0, read);
                }
            }
            byte[] digest = md5.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
