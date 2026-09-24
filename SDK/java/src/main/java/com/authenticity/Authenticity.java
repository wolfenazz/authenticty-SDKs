package com.authenticity;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticity client SDK for Java.
 *
 * <p>Implements every {@code /api/v1/client/*} endpoint of the Authenticity
 * authentication backend, mirroring the C++/C#/Python SDKs. It uses only the
 * JDK standard library (Java 11+, {@link HttpClient}), so it has no runtime
 * dependencies.</p>
 *
 * <p>Usage:</p>
 * <pre>{@code
 * Authenticity client = new Authenticity(
 *     "YOUR_OWNER_ID",
 *     "YOUR_APP_ID",
 *     "https://your-domain.example/api/v1/client",
 *     "1.0.0",
 *     "YOUR_LICENSE_KEY");
 * if (client.login()) {
 *     System.out.println("Welcome, " + client.getSession().getUsername());
 * } else {
 *     System.out.println("Login failed: " + client.getLastError());
 * }
 * }</pre>
 */
public class Authenticity {

    private final String mOwnerId;
    private final String mAppId;
    private final String mApiUrl;
    private final String mVersion;
    private String mLicenseKey;

    private final Session mSession = new Session();
    private final AppData mAppData = new AppData();
    private final String mHwid;
    private final String mHash;
    private String mLastError = "";

    private final HttpClient mHttp;

    /**
     * Constructs the client.
     *
     * @param ownerId     your owner ID from the dashboard
     * @param appId       your application ID from the dashboard
     * @param apiUrl      full API base URL, e.g. {@code https://.../api/v1/client}
     * @param version     your application version
     * @param licenseKey  optional license key for license-based login
     */
    public Authenticity(String ownerId, String appId, String apiUrl, String version,
                        String licenseKey) {
        mOwnerId = ownerId;
        mAppId = appId;
        mApiUrl = apiUrl == null ? "" : apiUrl.replaceAll("/+$", "");
        mVersion = version == null ? "" : version;
        mLicenseKey = licenseKey == null ? "" : licenseKey;
        mHwid = Hwid.generate();
        mHash = Hash.hashExecutable();
        mHttp = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Constructs the client without a default license key.
     */
    public Authenticity(String ownerId, String appId, String apiUrl, String version) {
        this(ownerId, appId, apiUrl, version, "");
    }

    // ------------------------------------------------------------------ //
    // Authentication
    // ------------------------------------------------------------------ //

    /**
     * Authenticate using the license key.
     *
     * @return true on success
     */
    public boolean login() {
        Map<String, Object> body = new HashMap<>();
        body.put("ownerId", mOwnerId);
        body.put("appId", mAppId);
        body.put("licenseKey", mLicenseKey);
        body.put("hwid", mHwid);
        body.put("version", mVersion);
        body.put("hash", mHash);

        String response = request("/auth/login", "POST", body);
        if (parseResponse(response)) {
            return true;
        }
        if ("Your IP address has been blacklisted".equals(Json.asString(Json.parse(response), "message"))) {
            mLastError = "Your IP address has been blacklisted";
            return false;
        }
        mLastError = Json.asString(Json.parse(response), "message");
        return false;
    }

    /**
     * Authenticate using a username and password.
     *
     * @return true on success
     */
    public boolean loginWithCredentials(String username, String password) {
        Map<String, Object> body = new HashMap<>();
        body.put("ownerId", mOwnerId);
        body.put("appId", mAppId);
        body.put("username", username);
        body.put("password", password);
        body.put("hwid", mHwid);
        body.put("version", mVersion);
        body.put("hash", mHash);

        String response = request("/auth/login-user", "POST", body);
        if (parseResponse(response)) {
            return true;
        }
        if ("Your IP address has been blacklisted".equals(Json.asString(Json.parse(response), "message"))) {
            mLastError = "Your IP address has been blacklisted";
            return false;
        }
        mLastError = Json.asString(Json.parse(response), "message");
        return false;
    }

    /** Check for a server update before login. Returns null on failure. */
    public UpdateInfo checkForUpdate() {
        Map<String, Object> body = new HashMap<>();
        body.put("ownerId", mOwnerId);
        body.put("appId", mAppId);
        body.put("version", mVersion);
        Map<String, Object> json = Json.parse(request("/app/update", "POST", body));
        if (!"true".equals(Json.asString(json, "success"))) {
            mLastError = Json.asString(json, "message");
            return null;
        }
        String clientVersion = Json.asString(json, "clientVersion");
        return new UpdateInfo(
                "true".equals(Json.asString(json, "updateRequired")),
                clientVersion.isEmpty() ? mVersion : clientVersion,
                Json.asString(json, "currentVersion"),
                Json.asString(json, "updateLink"),
                Json.asString(json, "appName"),
                Json.asString(json, "appStatus"));
    }

    /**
     * Register a new user with a license key.
     *
     * @return true on success
     */
    public boolean register(String username, String password, String licenseKey) {
        Map<String, Object> body = new HashMap<>();
        body.put("ownerId", mOwnerId);
        body.put("appId", mAppId);
        body.put("username", username);
        body.put("password", password);
        body.put("licenseKey", licenseKey == null ? mLicenseKey : licenseKey);
        body.put("hwid", mHwid);
        body.put("version", mVersion);
        body.put("hash", mHash);

        String response = request("/auth/register", "POST", body);
        if ("true".equals(Json.asString(Json.parse(response), "success"))) {
            return true;
        }
        mLastError = Json.asString(Json.parse(response), "message");
        return false;
    }

    /**
     * Validate the current session (heartbeat).
     *
     * @return true while the session is valid
     */
    public boolean checkSession() {
        if (!mSession.isValid()) {
            return false;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("hwid", mHwid);

        String response = request("/auth/check", "POST", body);
        Map<String, Object> json = Json.parse(response);
        if ("true".equals(Json.asString(json, "success"))) {
            applySubscriptionFields(json);
            return true;
        }

        boolean expired = "true".equals(Json.asString(json, "expired"));
        String reason = Json.asString(json, "reason");
        if (reason.isEmpty()) {
            reason = Json.asString(json, "message");
        }
        mSession.setValid(false);
        if (expired) {
            if ("License expired".equals(reason)) {
                mLastError = "Your license has expired. The application will now close.";
            } else if ("Session expired".equals(reason)) {
                mLastError = "Your session has expired. Please log in again.";
            } else {
                mLastError = reason.isEmpty() ? "Session is no longer valid" : reason;
            }
        } else {
            mLastError = Json.asString(json, "message");
            if (mLastError.isEmpty()) {
                mLastError = "Session is no longer valid";
            }
        }
        return false;
    }

    /** Ask the server whether the active subscription grants a feature. */
    public boolean hasFeature(String feature) {
        if (feature == null || feature.trim().isEmpty() || !mSession.isValid() || mSession.getToken().isEmpty()) return false;
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("hwid", mHwid);
        body.put("feature", feature);
        Map<String, Object> response = Json.parse(request("/auth/check", "POST", body));
        if (!"true".equals(Json.asString(response, "success"))) return false;
        applySubscriptionFields(response);
        return true;
    }

    private void applySubscriptionFields(Map<String, Object> json) {
        if (json.containsKey("subscriptionId")) mSession.setSubscriptionId(Json.asString(json, "subscriptionId"));
        if (json.containsKey("subscriptionName")) mSession.setSubscriptionName(Json.asString(json, "subscriptionName"));
        if (json.containsKey("level")) {
            try { mSession.setLevel(Integer.parseInt(Json.asString(json, "level"))); } catch (NumberFormatException ignored) { }
        }
        if (json.containsKey("features")) {
            List<String> features = new ArrayList<>();
            for (Object item : Json.asList(json, "features")) if (item instanceof String) features.add((String) item);
            mSession.setFeatures(features);
        }
        Object rawLimits = Json.get(json, "limits");
        if (rawLimits instanceof Map) {
            Map<String, Integer> limits = new HashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) rawLimits).entrySet()) {
                if (entry.getKey() instanceof String && entry.getValue() instanceof Number && ((Number) entry.getValue()).intValue() >= 0)
                    limits.put((String) entry.getKey(), ((Number) entry.getValue()).intValue());
            }
            mSession.setLimits(limits);
        }
    }

    /**
     * Check whether this client (IP / HWID) is blacklisted.
     *
     * @return true if blacklisted (caller should normally refuse to run)
     */
    public boolean checkBlacklist() {
        Map<String, Object> body = new HashMap<>();
        body.put("ownerId", mOwnerId);
        body.put("appId", mAppId);
        body.put("hwid", mHwid);

        String response = request("/auth/check-blacklist", "POST", body);
        String message = Json.asString(Json.parse(response), "message");
        if (isBlacklisted(response, message)) {
            mLastError = message.isEmpty() ? "Your IP address has been blacklisted" : message;
            return true;
        }
        return false;
    }

    /**
     * Self-ban the current session (usually called on tamper detection).
     *
     * @return true on success
     */
    public boolean ban(String reason) {
        if (!mSession.isValid()) {
            return false;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("reason", reason);

        String response = request("/auth/ban", "POST", body);
        mSession.setValid(false);
        return "true".equals(Json.asString(Json.parse(response), "success"));
    }


    // ------------------------------------------------------------------ //
    // Remote configuration / files / webhooks / logs
    // ------------------------------------------------------------------ //

    /**
     * Fetch a remote variable value by name (empty string if not found).
     */
    public String getVariable(String name) {
        if (!mSession.isValid()) {
            return "";
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("name", name);
        String response = request("/vars/get", "POST", body);
        return Json.asString(Json.parse(response), "value");
    }

    /**
     * Download a file by ID or name and return its raw bytes.
     *
     * @return the file bytes, or an empty array on failure
     */
    public byte[] downloadFile(String fileId) {
        if (!mSession.isValid()) {
            mLastError = "Session is invalid";
            return new byte[0];
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("fileId", fileId);
        String response = request("/files/download", "POST", body);

        Map<String, Object> json = Json.parse(response);
        String message = Json.asString(json, "message");
        if (isBlacklisted(response, message)) {
            mSession.setValid(false);
            mLastError = message.isEmpty() ? "Your IP address has been blacklisted" : message;
            return new byte[0];
        }
        if (!"true".equals(Json.asString(json, "success"))) {
            mLastError = message.isEmpty() ? "Download failed" : message;
            return new byte[0];
        }
        String url = Json.asString(json, "url");
        if (url.isEmpty()) url = Json.asString(json, "downloadUrl");
        if (url.isEmpty()) {
            mLastError = "Download URL not found in response";
            return new byte[0];
        }
        try {
            return downloadBytes(url);
        } catch (IOException e) {
            mLastError = "Failed to download file: " + e.getMessage();
            return new byte[0];
        }
    }

    /**
     * Resolve a file and open its URL in the user's default browser.
     *
     * @return true if the file was resolved successfully
     */
    public boolean downloadFileDirect(String fileId) {
        if (!mSession.isValid()) {
            mLastError = "Session is invalid";
            return false;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("fileId", fileId);
        String response = request("/files/download", "POST", body);

        Map<String, Object> json = Json.parse(response);
        String message = Json.asString(json, "message");
        if (isBlacklisted(response, message)) {
            mSession.setValid(false);
            mLastError = message.isEmpty() ? "Your IP address has been blacklisted" : message;
            return false;
        }
        if ("true".equals(Json.asString(json, "success"))) {
            String url = Json.asString(json, "url");
            if (url.isEmpty()) url = Json.asString(json, "downloadUrl");
            if (!url.isEmpty() && openUrl(url)) {
                return true;
            }
            mLastError = "Download URL not found in response";
            return false;
        }
        mLastError = message.isEmpty() ? "Unknown error" : message;
        return false;
    }

    /**
     * Trigger a named webhook with optional custom data.
     *
     * @return true on success
     */
    public boolean triggerWebhook(String webhookName, String data) {
        if (!mSession.isValid()) {
            mLastError = "Session is invalid";
            return false;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("webhookName", webhookName);
        body.put("data", data == null ? "" : data);
        String response = request("/webhooks/trigger", "POST", body);
        return "true".equals(Json.asString(Json.parse(response), "success"));
    }

    /**
     * Send an application log entry to the dashboard.
     */
    public void log(String data, String type) {
        if (!mSession.isValid()) {
            return;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("data", data);
        body.put("type", (type == null || type.isEmpty()) ? "info" : type);
        request("/logs/add", "POST", body);
    }


    // ------------------------------------------------------------------ //
    // Chat
    // ------------------------------------------------------------------ //

    /**
     * Fetch the list of chat channels for this application.
     */
    public List<Map<String, Object>> getChannels() {
        List<Map<String, Object>> channels = new ArrayList<>();
        if (!mSession.isValid()) {
            mLastError = "Session is invalid";
            return channels;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        String response = request("/chat/channels", "POST", body);

        Map<String, Object> json = Json.parse(response);
        String message = Json.asString(json, "message");
        if (isBlacklisted(response, message)) {
            mSession.setValid(false);
            mLastError = message.isEmpty() ? "Your IP address has been blacklisted" : message;
            return channels;
        }
        if ("true".equals(Json.asString(json, "success"))) {
            return Json.asObjectList(json, "channels");
        }
        mLastError = message.isEmpty() ? "Unknown error" : message;
        return channels;
    }

    /**
     * Fetch messages from a specific channel (or {@code "all"} for every channel).
     */
    public List<Map<String, Object>> getMessages(String channelId) {
        List<Map<String, Object>> messages = new ArrayList<>();
        if (!mSession.isValid()) {
            mLastError = "Session is invalid";
            return messages;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("channelId", channelId);
        String response = request("/chat/messages", "POST", body);

        Map<String, Object> json = Json.parse(response);
        String message = Json.asString(json, "message");
        if (isBlacklisted(response, message)) {
            mSession.setValid(false);
            mLastError = message.isEmpty() ? "Your IP address has been blacklisted" : message;
            return messages;
        }
        if ("true".equals(Json.asString(json, "success"))) {
            return Json.asObjectList(json, "messages");
        }
        mLastError = message.isEmpty() ? "Unknown error" : message;
        return messages;
    }

    /**
     * Send a message to a channel.
     *
     * @return true on success
     */
    public boolean sendMessage(String channelId, String content) {
        if (!mSession.isValid()) {
            mLastError = "Session is invalid";
            return false;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        body.put("channelId", channelId);
        body.put("content", content);
        String response = request("/chat/messages", "PUT", body);

        Map<String, Object> json = Json.parse(response);
        String message = Json.asString(json, "message");
        if (isBlacklisted(response, message)) {
            mSession.setValid(false);
            mLastError = message.isEmpty() ? "Your IP address has been blacklisted" : message;
            return false;
        }
        boolean ok = "true".equals(Json.asString(json, "success"));
        mLastError = message.isEmpty() ? (ok ? "Message sent" : "Unknown error") : message;
        return ok;
    }

    /** Return the current user's chat identity, or null on failure. */
    public Map<String, Object> getChatProfile() {
        return chatProfileRequest("POST", null, null);
    }

    /** Update the current user's chat nickname and application avatar ID. */
    public Map<String, Object> updateChatProfile(String nickname, String avatarId) {
        return chatProfileRequest("PUT", nickname, avatarId);
    }

    private Map<String, Object> chatProfileRequest(String method, String nickname, String avatarId) {
        if (!mSession.isValid()) {
            mLastError = "Session is invalid";
            return null;
        }
        Map<String, Object> body = new HashMap<>();
        body.put("token", mSession.getToken());
        body.put("appId", mAppId);
        if ("PUT".equals(method)) {
            body.put("nickname", nickname);
            body.put("avatarId", avatarId);
        }
        String response = request("/chat/profile", method, body);
        Map<String, Object> json = Json.parse(response);
        String message = Json.asString(json, "message");
        if (isBlacklisted(response, message)) {
            mSession.setValid(false);
            mLastError = message.isEmpty() ? "Your IP address has been blacklisted" : message;
            return null;
        }
        if (!"true".equals(Json.asString(json, "success"))) {
            mLastError = message.isEmpty() ? "Failed to update chat profile" : message;
            return null;
        }
        mLastError = "";
        Map<String, Object> profile = new HashMap<>();
        profile.put("id", Json.asString(json, "profileId"));
        profile.put("nickname", Json.asString(json, "nickname"));
        profile.put("avatarId", Json.asString(json, "avatarId"));
        return profile;
    }


    // ------------------------------------------------------------------ //
    // Getters / helpers
    // ------------------------------------------------------------------ //

    public void setLicenseKey(String licenseKey) {
        mLicenseKey = licenseKey == null ? "" : licenseKey;
    }

    public Session getSession() {
        return mSession;
    }

    public AppData getAppData() {
        return mAppData;
    }

    public String getLastError() {
        return mLastError;
    }

    /**
     * @return the update link reported by the server (may be empty)
     */
    public String getUpdateLink() {
        return mSession.getUpdateLink();
    }

    /**
     * Compute the time remaining until license expiry as a human string,
     * e.g. {@code "0 Years : 0 Months : 0 Days : 12 Hours : 30 Mins"}.
     */
    public String getRemainingTime() {
        String expiry = mSession.getExpiry();
        if (!mSession.isValid() || expiry == null || expiry.isEmpty()) {
            return zeroTime();
        }
        // Lifetime licenses are returned by the server as the literal "Never".
        if ("never".equalsIgnoreCase(expiry.trim())) {
            return "Lifetime";
        }
        try {
            OffsetDateTime exp = parseIso(expiry);
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            long totalSecs = exp.toEpochSecond() - now.toEpochSecond();
            if (totalSecs <= 0) {
                return zeroTime();
            }
            long days = totalSecs / 86400;
            long hours = (totalSecs % 86400) / 3600;
            long minutes = (totalSecs % 3600) / 60;
            long years = days / 365;
            days %= 365;
            long months = days / 30;
            days %= 30;
            return years + " Years : " + months + " Months : " + days
                    + " Days : " + hours + " Hours : " + minutes + " Mins";
        } catch (Exception e) {
            return zeroTime();
        }
    }

    private static String zeroTime() {
        return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins";
    }

    private static OffsetDateTime parseIso(String value) throws DateTimeParseException {
        String s = value.trim();
        if (s.endsWith("Z")) {
            s = s.substring(0, s.length() - 1) + "+00:00";
        }
        return OffsetDateTime.parse(s);
    }

    // ------------------------------------------------------------------ //
    // Credential management (login.json auto-login)
    // ------------------------------------------------------------------ //

    /**
     * @return the path of the auto-login credentials file (next to the JVM main).
     */
    public static Path credentialsPath() {
        String dir = System.getProperty("user.dir", ".");
        return Paths.get(dir, "login.json");
    }

    /**
     * Save auto-login credentials to login.json.
     *
     * @param loginType    1 = license key, 2 = username/password
     * @param licenseKey   license key (when loginType == 1)
     * @param username     username (when loginType == 2)
     * @param password     password (when loginType == 2)
     */
    public static boolean saveCredentials(int loginType, String licenseKey,
                                          String username, String password) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("loginType", loginType);
            data.put("licenseKey", licenseKey == null ? "" : licenseKey);
            data.put("username", username == null ? "" : username);
            data.put("password", password == null ? "" : password);
            Files.write(credentialsPath(), toJson(data).getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Load and validate auto-login credentials from login.json.
     */
    public static SavedCredentials loadCredentials() {
        SavedCredentials creds = new SavedCredentials();
        try {
            Path path = credentialsPath();
            if (!Files.exists(path)) {
                return creds;
            }
            String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
            Map<String, Object> data = Json.parse(content);
            int type = 0;
            try {
                type = Integer.parseInt(Json.asString(data, "loginType"));
            } catch (NumberFormatException ignored) {
            }
            creds.setLoginType(type);
            creds.setLicenseKey(Json.asString(data, "licenseKey"));
            creds.setUsername(Json.asString(data, "username"));
            creds.setPassword(Json.asString(data, "password"));
            if (type == 1 && !creds.getLicenseKey().isEmpty()) {
                creds.setValid(true);
            } else if (type == 2 && !creds.getUsername().isEmpty()
                    && !creds.getPassword().isEmpty()) {
                creds.setValid(true);
            }
        } catch (Exception ignored) {
            // return invalid credentials
        }
        return creds;
    }

    /**
     * Delete the auto-login credentials file if it exists.
     */
    public static boolean deleteCredentials() {
        try {
            Path path = credentialsPath();
            if (Files.exists(path)) {
                Files.delete(path);
                return true;
            }
        } catch (IOException ignored) {
            // fall through
        }
        return false;
    }


    // ------------------------------------------------------------------ //
    // Internal HTTP / JSON utilities
    // ------------------------------------------------------------------ //

    private String request(String endpoint, String method, Map<String, Object> body) {
        String url = mApiUrl + endpoint;
        String payload = toJson(body);
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json")
                    .header("User-Agent", "Authenticity SDK/1.0 (Java)")
                    .header("Accept", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(payload));
            if (!mSession.getToken().isEmpty()) {
                builder.header("Authorization", "Bearer " + mSession.getToken());
            }
            HttpResponse<String> resp = mHttp.send(builder.build(),
                    HttpResponse.BodyHandlers.ofString());
            // The API returns JSON error bodies with 4xx/5xx status; read them anyway.
            return resp.body() == null ? "" : resp.body();
        } catch (IOException | InterruptedException e) {
            mLastError = "Network error: " + e.getMessage();
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return "{\"success\":\"false\",\"message\":\"" + e.getMessage() + "\"}";
        }
    }

    private byte[] downloadBytes(String url) throws IOException {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(60))
                    .header("User-Agent", "Authenticity SDK/1.0 (Java)")
                    .GET()
                    .build();
            HttpResponse<byte[]> resp = mHttp.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() >= 400) {
                throw new IOException("HTTP " + resp.statusCode());
            }
            return resp.body() == null ? new byte[0] : resp.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while downloading", e);
        }
    }

    private static boolean openUrl(String url) {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            ProcessBuilder pb;
            if (os.contains("win")) {
                pb = new ProcessBuilder("cmd", "/c", "start", "", url);
            } else if (os.contains("mac")) {
                pb = new ProcessBuilder("open", url);
            } else {
                pb = new ProcessBuilder("xdg-open", url);
            }
            pb.start();
            return true;
        } catch (IOException e) {
            return false;
        }
    }


    private boolean parseResponse(String response) {
        Map<String, Object> json = Json.parse(response);
        if (!"true".equals(Json.asString(json, "success"))) {
            mSession.setUpdateLink(Json.asString(json, "updateLink"));
            return false;
        }
        String token = Json.asString(json, "token");
        if (token.isEmpty()) {
            mSession.setValid(false);
            mSession.setUpdateLink(Json.asString(json, "updateLink"));
            mLastError = "authenticity: login response did not include a session token";
            return false;
        }
        mSession.setValid(true);
        mSession.setToken(token);
        mSession.setExpiry(Json.asString(json, "expiry"));
        mSession.setUsername(Json.asString(json, "username"));
        mSession.setIp(Json.asString(json, "ip"));
        mSession.setHwid(mHwid);
        mSession.setUpdateLink(Json.asString(json, "updateLink"));
        applySubscriptionFields(json);
        try {
            String level = Json.asString(json, "level");
            mSession.setLevel(level.isEmpty() ? 0 : Integer.parseInt(level));
        } catch (NumberFormatException ignored) {
            mSession.setLevel(0);
        }
        mAppData.setName(Json.asString(json, "appName"));
        mAppData.setVersion(Json.asString(json, "appVersion"));
        mAppData.setStatus(Json.asString(json, "appStatus"));
        mAppData.setHwidLock("true".equals(Json.asString(json, "hwidLock")));
        return true;
    }

    private static boolean isBlacklisted(String response, String message) {
        if (message != null) {
            String m = message.toLowerCase();
            return m.contains("blacklist") || m.contains("banned")
                    || m.contains("blocked") || m.contains("denied");
        }
        return false;
    }

    /**
     * Encode a {@code Map}/object graph into a JSON string.
     */
    static String toJson(Object value) {
        StringBuilder sb = new StringBuilder();
        writeJson(sb, value);
        return sb.toString();
    }

    private static void writeJson(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeJson(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeJson(sb, e.getValue());
            }
            sb.append('}');
        } else if (value instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeJson(sb, item);
            }
            sb.append(']');
        } else if (value instanceof String) {
            writeJsonString(sb, (String) value);
        } else if (value instanceof Boolean || value instanceof Number) {
            sb.append(value);
        } else {
            writeJsonString(sb, String.valueOf(value));
        }
    }

    private static void writeJsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    sb.append(c);
            }
        }
        sb.append('"');
    }
}
