#include "Authenticity.h"
#include "json.hpp"
#include <iostream>
#include <sstream>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <ctime>
#include <cstdio>
#include <intrin.h>
#include <algorithm>
#include <fstream>
#include <shellapi.h>
#include <regex>
#include <cctype>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")

#ifdef SendMessage
#undef SendMessage
#endif

#pragma comment(lib, "winhttp.lib")

namespace Authenticity {

    using json = nlohmann::json;

    namespace {
        std::string JsonError(const std::string& response, const std::string& fallback) {
            std::string message;
            try {
                const json parsed = json::parse(response);
                if (parsed.contains("message") && parsed["message"].is_string()) {
                    message = parsed["message"].get<std::string>();
                }
            } catch (...) {
                // Fall through to the stable SDK error.
            }
            return message.empty() ? fallback : message;
        }

        bool IsTrue(const std::string& value) {
            std::string normalized = value;
            std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return normalized == "true" || normalized == "1";
        }
    }

    Client::Client(const std::string& ownerId, const std::string& appId, const std::string& apiUrl, const std::string& version, const std::string& licenseKey)
        : m_OwnerId(ownerId), m_AppId(appId), m_ApiUrl(apiUrl), m_Version(version), m_LicenseKey(licenseKey)
    {
        while (!m_ApiUrl.empty() && m_ApiUrl.back() == '/') m_ApiUrl.pop_back();
        m_Session.token = "";
        m_Session.expiry = "";
        m_Session.username = "";
        m_Session.ip = "";
        m_Session.hwid = "";
        m_Session.level = 0;
        m_Session.isValid = false;
        m_Session.updateLink = "";
        
        m_AppData.name = "";
        m_AppData.version = "";
        m_AppData.status = "";
        m_AppData.hwidLock = false;
        
        m_Hwid = BuildHwid();
        m_Hash = GetHash();
        m_LastError = "";
    }

    bool Client::Login() {
        const json body = {
            {"ownerId", m_OwnerId}, {"appId", m_AppId},
            {"licenseKey", m_LicenseKey}, {"hwid", m_Hwid},
            {"version", m_Version}, {"hash", m_Hash}
        };
        return ApplyLoginResponse(SendRequest("/auth/login", "POST", body.dump()));
    }

    void Client::SetLicenseKey(const std::string& licenseKey) {
        m_LicenseKey = licenseKey;
    }

    bool Client::LoginWithCredentials(const std::string& username, const std::string& password) {
        const json body = {
            {"ownerId", m_OwnerId}, {"appId", m_AppId},
            {"username", username}, {"password", password},
            {"hwid", m_Hwid}, {"version", m_Version}, {"hash", m_Hash}
        };
        return ApplyLoginResponse(SendRequest("/auth/login-user", "POST", body.dump()));
    }

    bool Client::ApplyLoginResponse(const std::string& response) {
        m_Session.updateLink = GetJsonValue(response, "updateLink");
        if (!IsTrue(GetJsonValue(response, "success"))) {
            m_Session.isValid = false;
            m_LastError = JsonError(response, "Authentication failed");
            return false;
        }

        const std::string token = GetJsonValue(response, "token");
        if (token.empty()) {
            m_Session.isValid = false;
            m_Session.updateLink = GetJsonValue(response, "updateLink");
            m_LastError = "authenticity: login response did not include a session token";
            return false;
        }

        m_Session.isValid = true;
        m_Session.token = token;
        m_Session.expiry = GetJsonValue(response, "expiry");
        m_Session.username = GetJsonValue(response, "username");
        m_Session.ip = GetJsonValue(response, "ip");
        m_Session.hwid = GetJsonValue(response, "hwid");
        if (m_Session.hwid.empty()) m_Session.hwid = m_Hwid;
        try { m_Session.level = std::stoi(GetJsonValue(response, "level")); }
        catch (...) { m_Session.level = 0; }
        m_AppData.name = GetJsonValue(response, "appName");
        m_AppData.version = GetJsonValue(response, "appVersion");
        m_AppData.status = GetJsonValue(response, "appStatus");
        m_AppData.hwidLock = IsTrue(GetJsonValue(response, "hwidLock"));
        m_LastError.clear();
        return true;
    }

    UpdateInfo Client::CheckForUpdate() {
        const json body = {{"ownerId", m_OwnerId}, {"appId", m_AppId}, {"version", m_Version}};
        std::string response = SendRequest("/app/update", "POST", body.dump());
        UpdateInfo info{};
        info.updateRequired = IsTrue(GetJsonValue(response, "updateRequired"));
        info.clientVersion = GetJsonValue(response, "clientVersion");
        info.currentVersion = GetJsonValue(response, "currentVersion");
        info.updateLink = GetJsonValue(response, "updateLink");
        info.appName = GetJsonValue(response, "appName");
        info.appStatus = GetJsonValue(response, "appStatus");
        if (!IsTrue(GetJsonValue(response, "success"))) m_LastError = JsonError(response, "Update check failed");
        else m_LastError.clear();
        return info;
    }

    bool Client::Register(const std::string& username, const std::string& password, const std::string& licenseKey) {
        const json body = {{"ownerId", m_OwnerId}, {"appId", m_AppId},
                           {"username", username}, {"password", password},
                           {"licenseKey", licenseKey}, {"hwid", m_Hwid}};
        const std::string response = SendRequest("/auth/register", "POST", body.dump());
        if (IsTrue(GetJsonValue(response, "success"))) { m_LastError.clear(); return true; }
        m_LastError = JsonError(response, "Registration failed");
        return false;
    }

    bool Client::CheckSession() {
        if (!m_Session.isValid) return false;

        const json body = {{"token", m_Session.token}, {"appId", m_AppId}, {"hwid", m_Hwid}};
        std::string response = SendRequest("/auth/check", "POST", body.dump());
        
        if (IsTrue(GetJsonValue(response, "success"))) {
            m_LastError.clear();
            return true;
        }

        // Check if the session failed due to license expiration
        std::string isExpired = GetJsonValue(response, "expired");
        std::string reason = GetJsonValue(response, "reason");
        if (reason.empty()) reason = GetJsonValue(response, "message");
        
        if (IsTrue(isExpired)) {
            m_Session.isValid = false;
            
            // Set the last error with more specific information
            if (reason == "License expired") {
                m_LastError = "Your license has expired. The application will now close.";
            } else if (reason == "Session expired") {
                m_LastError = "Your session has expired. Please login again.";
            } else {
                m_LastError = JsonError(response, "Session validation failed");
            }
            
            return false;
        }

        m_Session.isValid = false;
        m_LastError = JsonError(response, "Session validation failed");
        return false;
    }

    std::string Client::GetVariable(const std::string& name) {
        if (!m_Session.isValid) { m_LastError = "Session is invalid"; return ""; }
        const json body = {{"token", m_Session.token}, {"appId", m_AppId}, {"name", name}};
        const std::string response = SendRequest("/vars/get", "POST", body.dump());
        if (!IsTrue(GetJsonValue(response, "success"))) {
            m_LastError = JsonError(response, "Failed to fetch variable");
            return "";
        }
        m_LastError.clear();
        return GetJsonValue(response, "value");
    }

    std::vector<unsigned char> Client::DownloadFile(const std::string& fileId) {
        if (!m_Session.isValid) { m_LastError = "Session is invalid"; return {}; }
        const json body = {{"token", m_Session.token}, {"appId", m_AppId}, {"fileId", fileId}};
        std::string response = SendRequest("/files/download", "POST", body.dump());
        std::string message = GetJsonValue(response, "message");

        if (IsBlacklistedResponse(response, message)) {
            m_Session.isValid = false;
            m_LastError = message.empty() ? "Your IP address has been blacklisted" : message;
            return {};
        }

        if (!IsTrue(GetJsonValue(response, "success"))) {
            m_LastError = message.empty() ? "Download failed" : message;
            return {};
        }

        std::string url = GetJsonValue(response, "url");
        if (url.empty()) url = GetJsonValue(response, "downloadUrl");
        if (url.empty()) {
            m_LastError = "Download URL not found in response";
            return {};
        }

        return DownloadBytes(url);
    }

    std::vector<unsigned char> Client::DownloadBytes(const std::string& url) {
        std::vector<unsigned char> bytes;
        HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

        std::string host;
        std::string path;
        INTERNET_PORT port = 443;
        bool isHttps = false;

        if (url.find("https://") == 0) {
            isHttps = true;
            size_t hostStart = 8;
            size_t hostEnd = url.find("/", hostStart);
            if (hostEnd != std::string::npos) {
                host = url.substr(hostStart, hostEnd - hostStart);
                path = url.substr(hostEnd);
            } else {
                host = url.substr(hostStart);
                path = "/";
            }
        } else if (url.find("http://") == 0) {
            port = INTERNET_DEFAULT_HTTP_PORT;
            size_t hostStart = 7;
            size_t hostEnd = url.find("/", hostStart);
            if (hostEnd != std::string::npos) {
                host = url.substr(hostStart, hostEnd - hostStart);
                path = url.substr(hostEnd);
            } else {
                host = url.substr(hostStart);
                path = "/";
            }
        } else {
            m_LastError = "Invalid download URL";
            return bytes;
        }

        // Check if host contains a port
        size_t portPos = host.find(":");
        if (portPos != std::string::npos) {
            try {
                port = (INTERNET_PORT)std::stoi(host.substr(portPos + 1));
            } catch (...) {}
            host = host.substr(0, portPos);
        }

        std::wstring wHost(host.begin(), host.end());
        std::wstring wPath(path.begin(), path.end());

        hSession = WinHttpOpen(L"Authenticity SDK/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            WinHttpSetTimeouts(hSession, 30000, 30000, 30000, 30000);
            hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
        }

        if (hConnect) {
            DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
            hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        }

        if (hRequest) {
            // WinHTTP validates HTTPS certificates using the system trust store.

            BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
            if (bResults) {
                bResults = WinHttpReceiveResponse(hRequest, NULL);
            }

            if (bResults) {
                DWORD dwSize = 0;
                do {
                    dwSize = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                    if (dwSize == 0) break;

                    char* pszOutBuffer = new char[dwSize];
                    DWORD dwDownloaded = 0;
                    if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                        for (DWORD i = 0; i < dwDownloaded; i++) {
                            bytes.push_back((unsigned char)pszOutBuffer[i]);
                        }
                    }
                    delete[] pszOutBuffer;
                } while (true);
            }
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return bytes;
    }

    bool Client::TriggerWebhook(const std::string& webhookName, const std::string& data) {
        if (!m_Session.isValid) { m_LastError = "Session is invalid"; return false; }
        const json body = {{"token", m_Session.token}, {"appId", m_AppId},
                           {"webhookName", webhookName}, {"data", data}};
        const std::string response = SendRequest("/webhooks/trigger", "POST", body.dump());
        const bool ok = IsTrue(GetJsonValue(response, "success"));
        if (!ok) m_LastError = JsonError(response, "Webhook trigger failed");
        else m_LastError.clear();
        return ok;
    }

    void Client::Log(const std::string& data, const std::string& type) {
        if (!m_Session.isValid) return;
        const json body = {{"token", m_Session.token}, {"appId", m_AppId},
                           {"data", data}, {"type", type.empty() ? "info" : type}};
        const std::string response = SendRequest("/logs/add", "POST", body.dump());
        if (!IsTrue(GetJsonValue(response, "success"))) m_LastError = JsonError(response, "Failed to add log");
    }

    bool Client::Ban(const std::string& reason) {
        if (!m_Session.isValid) { m_LastError = "Session is invalid"; return false; }
        const json body = {{"token", m_Session.token}, {"appId", m_AppId}, {"reason", reason}};
        const std::string response = SendRequest("/auth/ban", "POST", body.dump());
        const bool ok = IsTrue(GetJsonValue(response, "success"));
        m_Session.isValid = false;
        if (!ok) m_LastError = JsonError(response, "Ban request failed");
        else m_LastError.clear();
        return ok;
    }

    Session Client::GetSession() const {
        return m_Session;
    }

    AppData Client::GetAppData() const {
        return m_AppData;
    }

    std::string Client::GetLastError() const {
        return m_LastError;
    }

    std::string Client::GetHwid() const { return m_Hwid; }

    std::string Client::GetHash() const { return m_Hash; }

    std::string Client::GetUpdateLink() const {
        return m_Session.updateLink;
    }

    bool Client::CheckBlacklist() {
        const json body = {{"ownerId", m_OwnerId}, {"appId", m_AppId}, {"hwid", m_Hwid}};
        std::string response = SendRequest("/auth/check-blacklist", "POST", body.dump());
        std::string message = GetJsonValue(response, "message");
        if (IsTrue(GetJsonValue(response, "blacklisted")) || IsBlacklistedResponse(response, message)) {
            m_LastError = message.empty() ? "This device is blacklisted" : message;
            return true;
        }
        if (IsTrue(GetJsonValue(response, "success"))) m_LastError.clear();
        else m_LastError = JsonError(response, "Blacklist check failed");
        return false;
    }

    bool Client::DownloadFileDirect(const std::string& fileId) {
        if (!m_Session.isValid) {
            m_LastError = "Session is invalid";
            return false;
        }

        const json body = {{"token", m_Session.token}, {"appId", m_AppId}, {"fileId", fileId}};
        std::string response = SendRequest("/files/download", "POST", body.dump());
        std::string message = GetJsonValue(response, "message");

        if (IsBlacklistedResponse(response, message)) {
            m_Session.isValid = false;
            m_LastError = message.empty() ? "Your IP address has been blacklisted" : message;
            return false;
        }

        if (IsTrue(GetJsonValue(response, "success"))) {
            std::string url = GetJsonValue(response, "url");
            if (url.empty()) url = GetJsonValue(response, "downloadUrl");
            if (!url.empty()) {
                // Open URL in default browser
                ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
                return true;
            } else {
                m_LastError = "Download URL not found in response";
                return false;
            }
        }

        m_LastError = message.empty() ? "Unknown error" : message;
        return false;
    }

    std::vector<ChatChannel> Client::GetChannels() {
        std::vector<ChatChannel> channels;
        
        if (!m_Session.isValid) {
            m_LastError = "Session is invalid";
            return channels;
        }

        const json body = {{"token", m_Session.token}, {"appId", m_AppId}};
        std::string response = SendRequest("/chat/channels", "POST", body.dump());
        std::string message = GetJsonValue(response, "message");

        if (IsBlacklistedResponse(response, message)) {
            m_Session.isValid = false;
            m_LastError = message.empty() ? "Your IP address has been blacklisted" : message;
            return channels;
        }

        if (IsTrue(GetJsonValue(response, "success"))) {
            return ParseChannels(response);
        }

        m_LastError = message.empty() ? "Unknown error" : message;
        return channels;
    }

    std::vector<ChatMessage> Client::GetMessages(const std::string& channelId) {
        std::vector<ChatMessage> messages;
        
        if (!m_Session.isValid) {
            m_LastError = "Session is invalid";
            return messages;
        }

        const json body = {{"token", m_Session.token}, {"appId", m_AppId}, {"channelId", channelId}};
        std::string response = SendRequest("/chat/messages", "POST", body.dump());
        std::string message = GetJsonValue(response, "message");

        if (IsBlacklistedResponse(response, message)) {
            m_Session.isValid = false;
            m_LastError = message.empty() ? "Your IP address has been blacklisted" : message;
            return messages;
        }

        if (IsTrue(GetJsonValue(response, "success"))) {
            return ParseMessages(response);
        }

        m_LastError = message.empty() ? "Unknown error" : message;
        return messages;
    }

    bool Client::SendMessage(const std::string& channelId, const std::string& content) {
        if (!m_Session.isValid) {
            m_LastError = "Session is invalid";
            return false;
        }

        const json body = {{"token", m_Session.token}, {"appId", m_AppId},
                           {"channelId", channelId}, {"content", content}};
        std::string response = SendRequest("/chat/messages", "PUT", body.dump());
        std::string message = GetJsonValue(response, "message");

        if (IsBlacklistedResponse(response, message)) {
            m_Session.isValid = false;
            m_LastError = message.empty() ? "Your IP address has been blacklisted" : message;
            return false;
        }

        const bool ok = IsTrue(GetJsonValue(response, "success"));
        if (!ok) m_LastError = JsonError(response, "Failed to send message");
        else m_LastError.clear();
        return ok;
    }

    bool Client::GetChatProfile(ChatProfile& profile) {
        if (!m_Session.isValid) { m_LastError = "Session is invalid"; return false; }
        const json body = {{"token", m_Session.token}, {"appId", m_AppId}};
        const std::string response = SendRequest("/chat/profile", "POST", body.dump());
        if (!IsTrue(GetJsonValue(response, "success"))) {
            m_LastError = JsonError(response, "Failed to fetch chat profile");
            return false;
        }
        profile.id = GetJsonValue(response, "profileId");
        profile.nickname = GetJsonValue(response, "nickname");
        profile.avatarId = GetJsonValue(response, "avatarId");
        m_LastError.clear();
        return true;
    }

    bool Client::UpdateChatProfile(const std::string& nickname, const std::string& avatarId, ChatProfile& profile) {
        if (!m_Session.isValid) { m_LastError = "Session is invalid"; return false; }
        const json body = {{"token", m_Session.token}, {"appId", m_AppId},
                           {"nickname", nickname}, {"avatarId", avatarId}};
        const std::string response = SendRequest("/chat/profile", "PUT", body.dump());
        if (!IsTrue(GetJsonValue(response, "success"))) {
            m_LastError = JsonError(response, "Failed to update chat profile");
            return false;
        }
        profile.id = GetJsonValue(response, "profileId");
        profile.nickname = GetJsonValue(response, "nickname");
        profile.avatarId = GetJsonValue(response, "avatarId");
        m_LastError.clear();
        return true;
    }

    std::string Client::GetExecutableDirectory() {
        char filename[MAX_PATH];
        GetModuleFileNameA(NULL, filename, MAX_PATH);
        
        std::string path(filename);
        size_t lastSlash = path.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            return path.substr(0, lastSlash + 1);
        }
        return "";
    }

    bool Client::SaveCredentials(int loginType, const std::string& licenseKey, const std::string& username, const std::string& password) {
        try {
            std::string filePath = GetExecutableDirectory() + "login.json";
            std::ofstream file(filePath);
            if (!file.is_open()) return false;

            const json credentials = {
                {"loginType", loginType},
                {"licenseKey", licenseKey},
                {"username", username},
                {"password", password}
            };
            file << credentials.dump(4);
            
            file.close();
            return true;
        }
        catch (...) {
            return false;
        }
    }

    SavedCredentials Client::LoadCredentials() {
        SavedCredentials creds = { 0, "", "", "", false };

        try {
            std::string filePath = GetExecutableDirectory() + "login.json";
            std::ifstream file(filePath);
            if (!file.is_open()) return creds;

            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            if (content.empty()) return creds;

            std::string loginTypeStr = GetJsonValueStatic(content, "loginType");
            if (!loginTypeStr.empty()) {
                creds.loginType = std::stoi(loginTypeStr);
            }

            creds.licenseKey = GetJsonValueStatic(content, "licenseKey");
            creds.username = GetJsonValueStatic(content, "username");
            creds.password = GetJsonValueStatic(content, "password");

            // Validate credentials
            if (creds.loginType == 1 && !creds.licenseKey.empty()) {
                creds.isValid = true;
            } else if (creds.loginType == 2 && !creds.username.empty() && !creds.password.empty()) {
                creds.isValid = true;
            }
        }
        catch (...) {
            // Return invalid credentials on error
        }

        return creds;
    }

    bool Client::DeleteCredentials() {
        try {
            std::string filePath = GetExecutableDirectory() + "login.json";
            if (std::remove(filePath.c_str()) == 0) {
                return true;
            }
        }
        catch (...) {
            // Ignore errors
        }
        return false;
    }

    std::string Client::GetRemainingTime() {
        if (!m_Session.isValid || m_Session.expiry.empty()) return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins";

        // Lifetime licenses are returned by the server as the literal "Never".
        if (m_Session.expiry == "Never" || _stricmp(m_Session.expiry.c_str(), "Never") == 0) return "Lifetime";

        // Parse ISO 8601: 2025-12-21T14:33:58.000Z
        int y, m, d, h, min, s;
        if (sscanf_s(m_Session.expiry.c_str(), "%d-%d-%dT%d:%d:%d", &y, &m, &d, &h, &min, &s) != 6) {
            return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins";
        }

        std::tm expiry_tm = { 0 };
        expiry_tm.tm_year = y - 1900;
        expiry_tm.tm_mon = m - 1;
        expiry_tm.tm_mday = d;
        expiry_tm.tm_hour = h;
        expiry_tm.tm_min = min;
        expiry_tm.tm_sec = s;

        // Convert to time_t (UTC)
        std::time_t expiry_time = _mkgmtime(&expiry_tm);
        std::time_t now = std::time(nullptr);

        long long diff = (long long)difftime(expiry_time, now);
        if (diff <= 0) return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins";

        int days = diff / (24 * 3600);
        diff %= (24 * 3600);
        int hours = diff / 3600;
        diff %= 3600;
        int minutes = diff / 60;

        int years = days / 365;
        days %= 365;
        int months = days / 30;
        days %= 30;

        char buffer[128];
        sprintf_s(buffer, sizeof(buffer), "%d Years : %d Months : %d Days : %d Hours : %d Mins", years, months, days, hours, minutes);
        return std::string(buffer);
    }

    std::string Client::GetJsonValueFromObject(const std::string& obj, const std::string& key) {
        // Try standard format "key":
        std::string keyPattern = "\"" + key + "\":";
        size_t keyIndex = obj.find(keyPattern);
        
        // Try with space "key" :
        if (keyIndex == std::string::npos) {
            keyPattern = "\"" + key + "\" :";
            keyIndex = obj.find(keyPattern);
        }
        
        if (keyIndex == std::string::npos) return "";

        size_t valueStart = keyIndex + keyPattern.length();
        
        // Skip whitespace
        while (valueStart < obj.length() && std::isspace(obj[valueStart])) {
            valueStart++;
        }
        
        if (valueStart >= obj.length()) return "";

        if (obj[valueStart] == '"') {
            valueStart++;
            size_t valueEnd = obj.find("\"", valueStart);
            if (valueEnd == std::string::npos) return "";
            return obj.substr(valueStart, valueEnd - valueStart);
        } else {
            size_t valueEnd = obj.find(",", valueStart);
            if (valueEnd == std::string::npos) valueEnd = obj.length();
            return obj.substr(valueStart, valueEnd - valueStart);
        }
    }

    std::vector<ChatChannel> Client::ParseChannels(const std::string& json) {
        std::vector<ChatChannel> channels;
        try {
            const nlohmann::json root = nlohmann::json::parse(json);
            const auto it = root.find("channels");
            if (it == root.end() || !it->is_array()) return channels;
            for (const auto& item : *it) {
                if (!item.is_object()) continue;
                ChatChannel channel;
                channel.id = item.value("id", "");
                channel.name = item.value("name", "");
                channel.cooldownUnit = item.value("cooldownUnit", "");
                channel.cooldownTime = item.value("cooldownTime", 0);
                channels.push_back(channel);
            }
        } catch (const std::exception& ex) {
            m_LastError = "Error parsing channels: " + std::string(ex.what());
        }
        return channels;
    }

    std::vector<ChatMessage> Client::ParseMessages(const std::string& json) {
        std::vector<ChatMessage> messages;
        try {
            const nlohmann::json root = nlohmann::json::parse(json);
            const auto it = root.find("messages");
            if (it == root.end() || !it->is_array()) return messages;
            for (const auto& item : *it) {
                if (!item.is_object()) continue;
                ChatMessage message;
                message.id = item.value("id", "");
                message.channelId = item.value("channelId", "");
                message.senderId = item.value("senderId", "");
                message.sender = item.value("sender", item.value("author", ""));
                message.avatarId = item.value("avatarId", "");
                message.content = item.value("content", item.value("text", ""));
                message.timeSent = item.value("timeSent", item.value("time_sent", item.value("timestamp", "")));
                messages.push_back(message);
            }
        } catch (const std::exception& ex) {
            m_LastError = "Error parsing messages: " + std::string(ex.what());
        }
        return messages;
    }

    bool Client::IsBlacklistedResponse(const std::string& response, const std::string& message) {
        if (IsTrue(GetJsonValue(response, "success"))) return false;
        if (IsTrue(GetJsonValue(response, "blacklisted"))) return true;
        std::string lowerMessage = message;
        std::transform(lowerMessage.begin(), lowerMessage.end(), lowerMessage.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return lowerMessage.find("blacklist") != std::string::npos ||
               lowerMessage.find("blacklisted") != std::string::npos;
    }

    std::string Client::GetJsonValueStatic(const std::string& json, const std::string& key) {
        try {
            const auto parsed = nlohmann::json::parse(json);
            const auto it = parsed.find(key);
            if (it == parsed.end() || it->is_null()) return "";
            if (it->is_string()) return it->get<std::string>();
            if (it->is_boolean()) return it->get<bool>() ? "true" : "false";
            return it->dump();
        } catch (...) { return ""; }
    }

    std::string Client::BuildHwid() {
        std::stringstream ss;

        // 1. CPU ID
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        ss << std::hex << cpuInfo[0] << cpuInfo[3]; // EAX and EDX

        // 2. Volume Serial
        DWORD serialNumber = 0;
        if (GetVolumeInformationA("C:\\", NULL, 0, &serialNumber, NULL, NULL, NULL, 0)) {
            ss << std::hex << serialNumber;
        }

        // 3. Computer Name
        char compName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD compSize = sizeof(compName);
        if (GetComputerNameA(compName, &compSize)) {
            ss << compName;
        }

        // 4. BIOS Information (Registry)
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "BIOSVersion", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                ss << buffer;
            }
            RegCloseKey(hKey);
        }

        std::string raw = ss.str();
        
        // Simple stable hash (DJB2) to produce a clean hex string
        unsigned long long hash = 5381;
        for (char c : raw) {
            hash = ((hash << 5) + hash) + c;
        }

        // Second pass with different seed for more entropy
        unsigned long long hash2 = 0xDEADBEEF;
        for (char c : raw) {
            hash2 = ((hash2 << 5) + hash2) ^ c;
        }

        std::stringstream finalHwid;
        finalHwid << std::hex << std::uppercase << hash << hash2;
        
        return finalHwid.str();
    }

    std::string Client::GetHash() {
        char filename[MAX_PATH];
        GetModuleFileNameA(NULL, filename, MAX_PATH);

        HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return "";

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CloseHandle(hFile);
            return "";
        }

        HCRYPTHASH hHash = 0;
        if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "";
        }

        BYTE rgbFile[1024];
        DWORD cbRead = 0;
        while (ReadFile(hFile, rgbFile, 1024, &cbRead, NULL)) {
            if (cbRead == 0) break;
            if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                CloseHandle(hFile);
                return "";
            }
        }

        BYTE rgbHash[16];
        DWORD cbHash = 16;
        std::string hash = "";

        if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
            char hex[3];
            for (DWORD i = 0; i < cbHash; i++) {
                sprintf_s(hex, "%02x", rgbHash[i]);
                hash += hex;
            }
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);

        return hash;
    }

    std::string Client::SendRequest(const std::string& endpoint, const std::string& method, const std::string& body) {
        std::string response;
        HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

        // Simple URL parsing
        std::string host;
        std::string path;
        INTERNET_PORT port = 0;
        bool isHttps = false;

        if (m_ApiUrl.find("https://") == 0) {
            isHttps = true;
            port = INTERNET_DEFAULT_HTTPS_PORT;
            size_t hostStart = 8;
            size_t hostEnd = m_ApiUrl.find("/", hostStart);
            if (hostEnd != std::string::npos) {
                host = m_ApiUrl.substr(hostStart, hostEnd - hostStart);
                path = m_ApiUrl.substr(hostEnd);
            } else {
                host = m_ApiUrl.substr(hostStart);
                path = "";
            }
        } else if (m_ApiUrl.find("http://") == 0) {
            port = INTERNET_DEFAULT_HTTP_PORT;
            size_t hostStart = 7;
            size_t hostEnd = m_ApiUrl.find("/", hostStart);
            if (hostEnd != std::string::npos) {
                host = m_ApiUrl.substr(hostStart, hostEnd - hostStart);
                path = m_ApiUrl.substr(hostEnd);
            } else {
                host = m_ApiUrl.substr(hostStart);
                path = "";
            }
        } else {
            m_LastError = "Invalid API URL. Use an http(s) URL ending in /api/v1/client";
            return "";
        }

        // Check if host contains a port
        size_t portPos = host.find(":");
        if (portPos != std::string::npos) {
            std::string portStr = host.substr(portPos + 1);
            port = (INTERNET_PORT)std::stoi(portStr);
            host = host.substr(0, portPos);
        }

        std::wstring wHost(host.begin(), host.end());
        std::wstring wPath(path.begin(), path.end());
        std::wstring wEndpoint(endpoint.begin(), endpoint.end());
        std::wstring wFullRequestPath = wPath + wEndpoint;

        hSession = WinHttpOpen(L"Authenticity SDK/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            WinHttpSetTimeouts(hSession, 30000, 30000, 30000, 30000);
            hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
        }

        if (hConnect) {
            std::wstring wMethod(method.begin(), method.end());
            DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
            
            hRequest = WinHttpOpenRequest(hConnect, wMethod.c_str(), wFullRequestPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        }

        if (hRequest) {
            // WinHTTP validates HTTPS certificates using the system trust store.

            std::wstring headers = L"Content-Type: application/json\r\n";
            if (!m_Session.token.empty()) {
                headers += L"Authorization: Bearer " + std::wstring(m_Session.token.begin(), m_Session.token.end()) + L"\r\n";
            }

            BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1L, (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);

            if (bResults) {
                bResults = WinHttpReceiveResponse(hRequest, NULL);
            }

            if (bResults) {
                DWORD dwSize = 0;
                do {
                    dwSize = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                    if (dwSize == 0) break;

                    char* pszOutBuffer = new char[dwSize + 1];
                    ZeroMemory(pszOutBuffer, dwSize + 1);

                    DWORD dwDownloaded = 0;
                    if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                        response.append(pszOutBuffer, dwDownloaded);
                    }
                    delete[] pszOutBuffer;
                } while (dwSize > 0);
            }
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return response;
    }

    std::string Client::GetJsonValue(const std::string& json, const std::string& key) {
        try {
            const nlohmann::json parsed = nlohmann::json::parse(json);
            const auto it = parsed.find(key);
            if (it == parsed.end() || it->is_null()) return "";
            if (it->is_string()) return it->get<std::string>();
            if (it->is_boolean()) return it->get<bool>() ? "true" : "false";
            return it->dump();
        } catch (...) { return ""; }
    }

}
