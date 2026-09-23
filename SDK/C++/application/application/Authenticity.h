#pragma once

#include <string>
#include <vector>
#include <functional>
#include <map>

namespace Authenticity {

    struct Session {
        std::string token;
        std::string expiry;
        std::string username;
        std::string ip;
        std::string hwid;
        int level;
        bool isValid;
        std::string updateLink;
    };

    struct AppData {
        std::string name;
        std::string version;
        std::string status;
        bool hwidLock;
    };

    struct UpdateInfo {
        bool updateRequired;
        std::string clientVersion;
        std::string currentVersion;
        std::string updateLink;
        std::string appName;
        std::string appStatus;
    };

    struct SavedCredentials {
        int loginType;  // 1 = license key, 2 = username/password
        std::string licenseKey;
        std::string username;
        std::string password;
        bool isValid;
    };

    struct ChatChannel {
        std::string id;
        std::string name;
        std::string cooldownUnit;
        int cooldownTime;
    };

    struct ChatMessage {
        std::string id;
        std::string channelId;
        std::string senderId;
        std::string sender;
        std::string avatarId;
        std::string content;
        std::string timeSent;
    };

    struct ChatProfile {
        std::string id;
        std::string nickname;
        std::string avatarId;
    };

    class Client {
    public:
        virtual ~Client() = default;

        Client(const std::string& ownerId, const std::string& appId, const std::string& apiUrl, const std::string& version, const std::string& licenseKey);

        // Initialize and verify license. Returns true if successful.
        bool Login();

        // Set or update the license key
        void SetLicenseKey(const std::string& licenseKey);

        // Login using username and password
        bool LoginWithCredentials(const std::string& username, const std::string& password);

        // Register a new user with a license key
        bool Register(const std::string& username, const std::string& password, const std::string& licenseKey);

        // Check if the current session is still valid (Heartbeat)
        bool CheckSession();
        UpdateInfo CheckForUpdate();

        // Check if the current IP is blacklisted
        bool CheckBlacklist();

        // Get a remote variable value by name
        std::string GetVariable(const std::string& name);

        // Download a file by ID or name
        std::vector<unsigned char> DownloadFile(const std::string& fileId);

        // Download a file directly by opening URL in browser
        bool DownloadFileDirect(const std::string& fileId);

        // Trigger a webhook by name with custom data
        bool TriggerWebhook(const std::string& webhookName, const std::string& data);

        // Log an event to the dashboard
        void Log(const std::string& data, const std::string& type = "info");

        // Ban the current user (self-ban for tampering)
        bool Ban(const std::string& reason);

        // Get the current session information
        Session GetSession() const;

        // Get the update link from the session
        std::string GetUpdateLink() const;

        // Get application data
        AppData GetAppData() const;

        // Get the remaining time until license expiry in DD : HH : MM : SS format
        std::string GetRemainingTime();

        // Get the last error message from the API
        std::string GetLastError() const;

        // Get the machine identifiers sent to the API.
        std::string GetHwid() const;
        std::string GetHash() const;

        // Chat functionality
        std::vector<ChatChannel> GetChannels();
        std::vector<ChatMessage> GetMessages(const std::string& channelId);
        bool SendMessage(const std::string& channelId, const std::string& content);
        bool GetChatProfile(ChatProfile& profile);
        bool UpdateChatProfile(const std::string& nickname, const std::string& avatarId, ChatProfile& profile);

        // Static credential management methods
        static std::string GetExecutableDirectory();
        static bool SaveCredentials(int loginType, const std::string& licenseKey, const std::string& username, const std::string& password);
        static SavedCredentials LoadCredentials();
        static bool DeleteCredentials();

    private:
        std::string m_OwnerId;
        std::string m_AppId;
        std::string m_LicenseKey;
        std::string m_ApiUrl;
        Session m_Session;
        AppData m_AppData;
        std::string m_Hwid;
        std::string m_Version;
        std::string m_Hash;
        std::string m_LastError;

        // Internal helper to get hardware ID
        std::string BuildHwid();

        // Internal helper to get MD5 hash of the executable
        std::string GetHash();

        // Internal helper to send HTTP requests using WinHTTP
        std::string SendRequest(const std::string& endpoint, const std::string& method, const std::string& body);

        // Internal helper to download raw binary data from a URL
        std::vector<unsigned char> DownloadBytes(const std::string& url);

        // Simple JSON helper (internal)
        std::string GetJsonValue(const std::string& json, const std::string& key);

        // Apply the common login response shape returned by the API.
        bool ApplyLoginResponse(const std::string& response);
        
        // Enhanced JSON helpers for parsing arrays and objects
        std::string GetJsonValueFromObject(const std::string& obj, const std::string& key);
        std::vector<ChatChannel> ParseChannels(const std::string& json);
        std::vector<ChatMessage> ParseMessages(const std::string& json);
        
        // Enhanced blacklist detection
        bool IsBlacklistedResponse(const std::string& response, const std::string& message);
        
        // Static JSON helper for credential management
        static std::string GetJsonValueStatic(const std::string& json, const std::string& key);
    };

}
