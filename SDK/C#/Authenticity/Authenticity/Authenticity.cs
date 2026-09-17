using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization.Json;
using System.Net;
using System.Diagnostics;
using System.Web.Script.Serialization;



namespace Authenticity
{
    /// <summary>
    /// Represents the user's session information.
    /// </summary>
    public class Session
    {
        public string Token { get; set; } = "";
        public string Expiry { get; set; } = "";
        public string Username { get; set; } = "";
        public string IP { get; set; } = "";
        public string Hwid { get; set; } = "";
        public int Level { get; set; } = 0;
        public bool IsValid { get; set; } = false;
        public string UpdateLink { get; set; } = "";
    }

    /// <summary>
    /// Represents application data from the server.
    /// </summary>
    public class AppData
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string Status { get; set; } = "";
        public bool HwidLock { get; set; } = false;
    }

    /// <summary>Result of a pre-login application version check.</summary>
    public class UpdateInfo
    {
        public bool UpdateRequired { get; set; }
        public string ClientVersion { get; set; } = "";
        public string CurrentVersion { get; set; } = "";
        public string UpdateLink { get; set; } = "";
        public string AppName { get; set; } = "";
        public string AppStatus { get; set; } = "";
    }

    /// <summary>
    /// Structure for saved login credentials.
    /// </summary>
    public class SavedCredentials
    {
        public int LoginType { get; set; } = 0;  // 1 = license key, 2 = username/password
        public string LicenseKey { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public bool IsValid { get; set; } = false;
    }

    /// <summary>
    /// Authenticity SDK Client for C#
    /// Provides authentication, session management, and API communication.
    /// </summary>
    public class Authenticity
    {
        private readonly string m_OwnerId;
        private readonly string m_AppId;
        private readonly string m_ApiUrl;
        private readonly string m_Version;
        private string m_LicenseKey;
        private Session m_Session;
        private AppData m_AppData;
        private string m_Hwid;
        private string m_Hash;
        private string m_LastError;
        private static readonly HttpClient httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        private static readonly JavaScriptSerializer jsonSerializer = new JavaScriptSerializer();

        /// <summary>
        /// Initializes a new instance of the AuthenticityClient.
        /// </summary>
        /// <param name="ownerId">Your owner ID from the dashboard</param>
        /// <param name="appId">Your application ID from the dashboard</param>
        /// <param name="apiUrl">The API URL (for example, https://your-domain.example/api/v1/client)</param>
        /// <param name="version">Your application version</param>
        /// <param name="licenseKey">Optional license key for license-based login</param>
        public Authenticity(string ownerId, string appId, string apiUrl, string version, string licenseKey = "")
        {
            // Ensure TLS 1.2 is used (required for Vercel)
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            m_OwnerId = ownerId;
            m_AppId = appId;
            m_ApiUrl = apiUrl.TrimEnd('/');
            m_Version = version;
            m_LicenseKey = licenseKey;
            m_Session = new Session();
            m_AppData = new AppData();
            m_Hwid = GetHwid();
            m_Hash = GetHash();
            m_LastError = "";
        }



        /// <summary>
        /// Set or update the license key.
        /// </summary>
        public void SetLicenseKey(string licenseKey)
        {
            m_LicenseKey = licenseKey;
        }

        /// <summary>
        /// Login using the license key.
        /// </summary>
        /// <returns>True if login was successful</returns>
        public bool Login()
        {
            try
            {
                var body = new Dictionary<string, string>
                {
                    { "ownerId", m_OwnerId },
                    { "appId", m_AppId },
                    { "licenseKey", m_LicenseKey },
                    { "hwid", m_Hwid },
                    { "version", m_Version },
                    { "hash", m_Hash }
                };

                Console.WriteLine("API URL: " + m_ApiUrl + "/auth/login");

                string response = SendRequest("/auth/login", "POST", DictionaryToJson(body));

                Console.WriteLine("Response status code: " + (response.Contains("\"success\":\"false\"") ? "Failed" : "Success"));

                // Check for blacklist response in multiple ways
                string success = GetJsonValue(response, "success");
                string message = GetJsonValue(response, "message");
                m_Session.UpdateLink = GetJsonValue(response, "updateLink");


                // Enhanced blacklist detection - check both message field and raw response
                bool isBlacklisted = false;
                string blacklistMessage = "Your IP address has been blacklisted";

                // Check if the message contains blacklist information
                if (!string.IsNullOrEmpty(message) &&
                    (message.ToLower().Contains("blacklist") ||
                     message.ToLower().Contains("blacklisted")))
                {
                    isBlacklisted = true;
                    blacklistMessage = message;
                }
                // Also check the raw response for blacklist keywords
                else if (IsBlacklistResponse(response, message))
                {
                    isBlacklisted = true;
                    // Try to extract the exact message, otherwise use default
                    if (!string.IsNullOrEmpty(message))
                    {
                        blacklistMessage = message;
                    }
                }

                if (isBlacklisted)
                {
                    m_LastError = blacklistMessage;
                    Console.WriteLine("Blacklist detected: " + m_LastError);
                    return false;
                }

                if (success == "true")
                {
                    string sessionToken = GetJsonValue(response, "token");
                    if (string.IsNullOrEmpty(sessionToken))
                    {
                        m_Session.IsValid = false;
                        m_LastError = "authenticity: login response did not include a session token";
                        return false;
                    }
                    m_Session.IsValid = true;
                    m_Session.Token = sessionToken;
                    m_Session.Expiry = GetJsonValue(response, "expiry");
                    m_Session.Username = GetJsonValue(response, "username");
                    m_Session.IP = GetJsonValue(response, "ip");
                    m_Session.Hwid = m_Hwid;
                    
                    m_Session.UpdateLink = GetJsonValue(response, "updateLink");
                    
                    string levelStr = GetJsonValue(response, "level");
                    m_Session.Level = string.IsNullOrEmpty(levelStr) ? 0 : int.Parse(levelStr);

                    m_AppData.Name = GetJsonValue(response, "appName");
                    m_AppData.Version = GetJsonValue(response, "appVersion");
                    m_AppData.Status = GetJsonValue(response, "appStatus");
                    m_AppData.HwidLock = GetJsonValue(response, "hwidLock") == "true";

                    return true;
                }
                else if (message == "Invalid license key")
                {
                    m_LastError = "Invalid license key";
                    Console.WriteLine("Invalid license key: " + m_LastError);
                    return false;
                }
                else if (message == "License expired")
                {
                    m_LastError = "License expired";
                    Console.WriteLine("License expired: " + m_LastError);
                    return false;
                }
                else
                {
                    m_LastError = message ?? "Unknown error";
                    Console.WriteLine("Login failed with message: " + m_LastError);
                    return false;
                }
            }
            catch (Exception ex)
            {
                m_LastError = ex.Message;
                Console.WriteLine("Login exception: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Login using username and password.
        /// </summary>
        /// <param name="username">The username</param>
        /// <param name="password">The password</param>
        /// <returns>True if login was successful</returns>
        public bool LoginWithCredentials(string username, string password)
        {
            try
            {
                var body = new Dictionary<string, string>
                {
                    { "ownerId", m_OwnerId },
                    { "appId", m_AppId },
                    { "username", username },
                    { "password", password },
                    { "hwid", m_Hwid },
                    { "version", m_Version },
                    { "hash", m_Hash }
                };

                Console.WriteLine("API URL: " + m_ApiUrl + "/auth/login-user");

                string response = SendRequest("/auth/login-user", "POST", DictionaryToJson(body));

                Console.WriteLine("Response status code: " + (response.Contains("\"success\":\"false\"") ? "Failed" : "Success"));

                // Check for blacklist response in multiple ways
                string success = GetJsonValue(response, "success");
                string message = GetJsonValue(response, "message");
                m_Session.UpdateLink = GetJsonValue(response, "updateLink");


                // Enhanced blacklist detection - check both message field and raw response
                bool isBlacklisted = false;
                string blacklistMessage = "Your IP address has been blacklisted";

                // Check if the message contains blacklist information
                if (!string.IsNullOrEmpty(message) &&
                    (message.ToLower().Contains("blacklist") ||
                     message.ToLower().Contains("blacklisted")))
                {
                    isBlacklisted = true;
                    blacklistMessage = message;
                }
                // Also check the raw response for blacklist keywords
                else if (IsBlacklistResponse(response, message))
                {
                    isBlacklisted = true;
                    // Try to extract the exact message, otherwise use default
                    if (!string.IsNullOrEmpty(message))
                    {
                        blacklistMessage = message;
                    }
                }

                if (isBlacklisted)
                {
                    m_LastError = blacklistMessage;
                    Console.WriteLine("Blacklist detected: " + m_LastError);
                    return false;
                }

                if (success == "true")
                {
                    string sessionToken = GetJsonValue(response, "token");
                    if (string.IsNullOrEmpty(sessionToken))
                    {
                        m_Session.IsValid = false;
                        m_LastError = "authenticity: login response did not include a session token";
                        return false;
                    }
                    m_Session.IsValid = true;
                    m_Session.Token = sessionToken;
                    m_Session.Expiry = GetJsonValue(response, "expiry");
                    m_Session.Username = GetJsonValue(response, "username");
                    m_Session.IP = GetJsonValue(response, "ip");
                    m_Session.Hwid = m_Hwid;
                    
                    m_Session.UpdateLink = GetJsonValue(response, "updateLink");

                    string levelStr = GetJsonValue(response, "level");
                    m_Session.Level = string.IsNullOrEmpty(levelStr) ? 0 : int.Parse(levelStr);

                    m_AppData.Name = GetJsonValue(response, "appName");
                    m_AppData.Version = GetJsonValue(response, "appVersion");
                    m_AppData.Status = GetJsonValue(response, "appStatus");
                    m_AppData.HwidLock = GetJsonValue(response, "hwidLock") == "true";

                    return true;
                }
                else if (message == "Invalid password")
                {
                    m_LastError = "Invalid password";
                    Console.WriteLine("Invalid password: " + m_LastError);
                    return false;
                }
                else if (message == "User not found")
                {
                    m_LastError = "User not found";
                    Console.WriteLine("User not found: " + m_LastError);
                    return false;
                }
                else
                {
                    m_LastError = message ?? "Unknown error";
                    Console.WriteLine("Login failed with message: " + m_LastError);
                    return false;
                }
            }
            catch (Exception ex)
            {
                m_LastError = ex.Message;
                Console.WriteLine("Login exception: " + ex.Message);
                return false;
            }
        }

        /// <summary>Check for a server update before login.</summary>
        public UpdateInfo CheckForUpdate()
        {
            var body = new Dictionary<string, string>
            {
                { "ownerId", m_OwnerId },
                { "appId", m_AppId },
                { "version", m_Version }
            };
            string response = SendRequest("/app/update", "POST", DictionaryToJson(body));
            if (GetJsonValue(response, "success") != "true")
            {
                m_LastError = GetJsonValue(response, "message");
                if (string.IsNullOrEmpty(m_LastError)) m_LastError = "Update check failed";
                return null;
            }
            m_LastError = "";
            return new UpdateInfo
            {
                UpdateRequired = GetJsonValue(response, "updateRequired") == "true",
                ClientVersion = GetJsonValue(response, "clientVersion") ?? m_Version,
                CurrentVersion = GetJsonValue(response, "currentVersion"),
                UpdateLink = GetJsonValue(response, "updateLink"),
                AppName = GetJsonValue(response, "appName"),
                AppStatus = GetJsonValue(response, "appStatus")
            };
        }

        /// <summary>
        /// Register a new user with a license key.
        /// </summary>
        /// <param name="username">The username</param>
        /// <param name="password">The password</param>
        /// <param name="licenseKey">The license key to activate</param>
        /// <returns>True if registration was successful</returns>
        public bool Register(string username, string password, string licenseKey)
        {
            try
            {
                var body = new Dictionary<string, string>
                {
                    { "ownerId", m_OwnerId },
                    { "appId", m_AppId },
                    { "username", username },
                    { "password", password },
                    { "licenseKey", licenseKey },
                    { "hwid", m_Hwid },
                    { "version", m_Version },
                    { "hash", m_Hash }
                };

                string response = SendRequest("/auth/register", "POST", DictionaryToJson(body));
                string message = GetJsonValue(response, "message");

                // Enhanced blacklist detection
                bool isBlacklisted = false;
                string blacklistMessage = "Your IP address has been blacklisted";

                if (!string.IsNullOrEmpty(message) &&
                    (message.ToLower().Contains("blacklist") ||
                     message.ToLower().Contains("blacklisted")))
                {
                    isBlacklisted = true;
                    blacklistMessage = message;
                }
                else if (IsBlacklistResponse(response, message))
                {
                    isBlacklisted = true;
                    if (!string.IsNullOrEmpty(message))
                    {
                        blacklistMessage = message;
                    }
                }

                if (isBlacklisted)
                {
                    m_LastError = blacklistMessage;
                    Console.WriteLine("Blacklist detected during registration: " + m_LastError);
                    return false;
                }

                if (GetJsonValue(response, "success") == "true")
                {
                    return true;
                }

                m_LastError = message ?? "Unknown error";
                return false;
            }
            catch (Exception ex)
            {
                m_LastError = ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Check if the current session is still valid (heartbeat).
        /// </summary>
        /// <returns>True if session is valid</returns>
        public bool CheckSession()
        {
            if (!m_Session.IsValid) return false;

            try
            {
                var body = new Dictionary<string, string>
                {
                    { "token", m_Session.Token },
                    { "appId", m_AppId },
                    { "hwid", m_Hwid }
                };

                string response = SendRequest("/auth/check", "POST", DictionaryToJson(body));
                string message = GetJsonValue(response, "message");

                if (IsBlacklistResponse(response, message))
                {
                    m_Session.IsValid = false;
                    m_LastError = string.IsNullOrEmpty(message) ? "Your IP address has been blacklisted" : message;
                    return false;
                }

                if (GetJsonValue(response, "success") == "true")
                {
                    return true;
                }

                // Check if session failed due to expiration
                string isExpired = GetJsonValue(response, "expired");
                string reason = GetJsonValue(response, "reason");
                if (string.IsNullOrEmpty(reason))
                {
                    reason = message;
                }

                if (isExpired == "true")
                {
                    m_Session.IsValid = false;

                    if (reason == "License expired")
                    {
                        m_LastError = "Your license has expired. The application will now close.";
                    }
                    else if (reason == "Session expired")
                    {
                        m_LastError = "Your session has expired. Please login again.";
                    }
                    else
                    {
                        m_LastError = string.IsNullOrEmpty(reason) ? "Session validation failed" : reason;
                    }

                    return false;
                }

                m_Session.IsValid = false;
                m_LastError = string.IsNullOrEmpty(message) ? "Session validation failed" : message;
                return false;
            }
            catch (Exception ex)
            {
                m_LastError = ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Check if the current IP is blacklisted.
        /// </summary>
        /// <returns>True if IP is blacklisted</returns>
        public bool CheckBlacklist()
        {
            try
            {
                var body = new Dictionary<string, string>
                {
                    { "ownerId", m_OwnerId },
                    { "appId", m_AppId },
                    { "hwid", m_Hwid }
                };

                string response = SendRequest("/auth/check-blacklist", "POST", DictionaryToJson(body));
                string message = GetJsonValue(response, "message");

                bool isBlacklisted = IsBlacklistResponse(response, message);
                if (isBlacklisted)
                {
                    m_LastError = string.IsNullOrEmpty(message) ? "Your IP address has been blacklisted" : message;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                m_LastError = ex.Message;
                Console.WriteLine("Blacklist check exception: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Get a remote variable value by name.
        /// </summary>
        /// <param name="name">The variable name</param>
        /// <returns>The variable value or empty string</returns>
        public string GetVariable(string name)
        {
            if (!m_Session.IsValid) return "";

            try
            {
                var body = new Dictionary<string, string>
                {
                    { "token", m_Session.Token },
                    { "appId", m_AppId },
                    { "name", name }
                };

                string response = SendRequest("/vars/get", "POST", DictionaryToJson(body));
                string message = GetJsonValue(response, "message");

                // Enhanced blacklist detection
                bool isBlacklisted = false;
                string blacklistMessage = "Your IP address has been blacklisted";

                if (!string.IsNullOrEmpty(message) &&
                    (message.ToLower().Contains("blacklist") ||
                     message.ToLower().Contains("blacklisted")))
                {
                    isBlacklisted = true;
                    blacklistMessage = message;
                }
                else if (IsBlacklistResponse(response, message))
                {
                    isBlacklisted = true;
                    if (!string.IsNullOrEmpty(message))
                    {
                        blacklistMessage = message;
                    }
                }

                if (isBlacklisted)
                {
                    m_Session.IsValid = false;
                    m_LastError = blacklistMessage;
                    Console.WriteLine("Blacklist detected during variable retrieval: " + m_LastError);
                    return "";
                }

                string success = GetJsonValue(response, "success");
                if (!string.Equals(success, "true", StringComparison.OrdinalIgnoreCase))
                {
                    m_LastError = string.IsNullOrEmpty(message) ? "Variable lookup failed" : message;
                    return "";
                }
                return GetJsonValue(response, "value");
            }
            catch (Exception ex)
            {
                m_LastError = ex.Message;
                return "";
            }
        }

        /// <summary>
        /// Download a file by ID.
        /// </summary>
        /// <param name="fileId">The file ID</param>
        /// <returns>The file content as bytes</returns>
        public byte[] DownloadFile(string fileId)
        {
            if (!m_Session.IsValid) return new byte[0];

            try
            {
                var body = new Dictionary<string, string>
                {
                    { "token", m_Session.Token },
                    { "appId", m_AppId },
                    { "fileId", fileId }
                };

                string response = SendRequest("/files/download", "POST", DictionaryToJson(body));
                string message = GetJsonValue(response, "message");

                if (IsBlacklistResponse(response, message))
                {
                    m_Session.IsValid = false;
                    m_LastError = string.IsNullOrEmpty(message) ? "Your IP address has been blacklisted" : message;
                    return new byte[0];
                }

                if (GetJsonValue(response, "success") != "true")
                {
                    m_LastError = string.IsNullOrEmpty(message) ? "Download failed" : message;
                    return new byte[0];
                }

                // The API returns the canonical storage URL; download the actual bytes from it.
                string downloadUrl = GetJsonValue(response, "downloadUrl");
                if (string.IsNullOrEmpty(downloadUrl))
                {
                    downloadUrl = GetJsonValue(response, "url");
                }
                if (string.IsNullOrEmpty(downloadUrl))
                {
                    m_LastError = "Download URL not found in response";
                    return new byte[0];
                }

                return httpClient.GetByteArrayAsync(downloadUrl).Result;
            }
            catch (Exception ex)
            {
                m_LastError = ex.Message;
                return new byte[0];
            }
        }

        /// <summary>
        /// Trigger a webhook by name with custom data.
        /// </summary>
        /// <param name="webhookName">The webhook name</param>
        /// <param name="data">The data to send</param>
        /// <returns>True if webhook was triggered successfully</returns>
        public bool TriggerWebhook(string webhookName, string data)
        {
            if (!m_Session.IsValid) return false;

            try
            {
                var body = new Dictionary<string, string>
                {
                    { "token", m_Session.Token },
                    { "appId", m_AppId },
                    { "webhookName", webhookName },
                    { "data", data }
                };

                string response = SendRequest("/webhooks/trigger", "POST", DictionaryToJson(body));
                string message = GetJsonValue(response, "message");

                // Enhanced blacklist detection
                bool isBlacklisted = false;
                string blacklistMessage = "Your IP address has been blacklisted";

                if (!string.IsNullOrEmpty(message) &&
                    (message.ToLower().Contains("blacklist") ||
                     message.ToLower().Contains("blacklisted")))
                {
                    isBlacklisted = true;
                    blacklistMessage = message;
                }
                else if (IsBlacklistResponse(response, message))
                {
                    isBlacklisted = true;
                    if (!string.IsNullOrEmpty(message))
                    {
                        blacklistMessage = message;
                    }
                }

                if (isBlacklisted)
                {
                    m_Session.IsValid = false;
                    m_LastError = blacklistMessage;
                    Console.WriteLine("Blacklist detected during webhook trigger: " + m_LastError);
                    return false;
                }

                return GetJsonValue(response, "success") == "true";
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Log an event to the dashboard.
        /// </summary>
        /// <param name="data">The log data</param>
        /// <param name="type">The log type (info, warning, error)</param>
        public void Log(string data, string type = "info")
        {
            if (!m_Session.IsValid) return;

            try
            {
                var body = new Dictionary<string, string>
                {
                    { "token", m_Session.Token },
                    { "appId", m_AppId },
                    { "data", data },
                    { "type", type }
                };

                SendRequest("/logs/add", "POST", DictionaryToJson(body));
            }
            catch
            {
                // Silently fail for logging
            }
        }

        /// <summary>
        /// Ban the current user (self-ban for tampering detection).
        /// </summary>
        /// <param name="reason">The ban reason</param>
        /// <returns>True if ban was successful</returns>
        public bool Ban(string reason)
        {
            if (!m_Session.IsValid) return false;

            try
            {
                var body = new Dictionary<string, string>
                {
                    { "token", m_Session.Token },
                    { "appId", m_AppId },
                    { "reason", reason }
                };

                string response = SendRequest("/auth/ban", "POST", DictionaryToJson(body));
                string message = GetJsonValue(response, "message");

                // Enhanced blacklist detection
                bool isBlacklisted = false;
                string blacklistMessage = "Your IP address has been blacklisted";

                if (!string.IsNullOrEmpty(message) &&
                    (message.ToLower().Contains("blacklist") ||
                     message.ToLower().Contains("blacklisted")))
                {
                    isBlacklisted = true;
                    blacklistMessage = message;
                }
                else if (IsBlacklistResponse(response, message))
                {
                    isBlacklisted = true;
                    if (!string.IsNullOrEmpty(message))
                    {
                        blacklistMessage = message;
                    }
                }

                if (isBlacklisted)
                {
                    m_Session.IsValid = false;
                    m_LastError = blacklistMessage;
                    Console.WriteLine("Blacklist detected during ban operation: " + m_LastError);
                    return false;
                }

                m_Session.IsValid = false;
                return GetJsonValue(response, "success") == "true";
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get the current session information.
        /// </summary>
        public Session GetSession()
        {
            return m_Session;
        }

        /// <summary>
        /// Get the update link from the session.
        /// </summary>
        public string GetUpdateLink()
        {
            return m_Session.UpdateLink;
        }

        /// <summary>
        /// Get the application data.
        /// </summary>
        public AppData GetAppData()
        {
            return m_AppData;
        }

        /// <summary>
        /// Get the last error message from the API.
        /// </summary>
        public string GetLastError()
        {
            return m_LastError;
        }

        /// <summary>
        /// Get the remaining time until license expiry in formatted string.
        /// </summary>
        /// <returns>Formatted remaining time string</returns>
        public string GetRemainingTime()
        {
            if (!m_Session.IsValid || string.IsNullOrEmpty(m_Session.Expiry))
                return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins";

            // Lifetime licenses are returned by the server as the literal "Never".
            if (m_Session.Expiry.Trim().Equals("Never", StringComparison.OrdinalIgnoreCase))
                return "Lifetime";

            try
            {
                // Parse ISO 8601: 2025-12-21T14:33:58.000Z
                DateTime expiryTime = DateTime.Parse(m_Session.Expiry).ToUniversalTime();
                DateTime now = DateTime.UtcNow;

                TimeSpan diff = expiryTime - now;
                if (diff.TotalSeconds <= 0)
                    return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins";

                int totalDays = (int)diff.TotalDays;
                int hours = diff.Hours;
                int minutes = diff.Minutes;

                int years = totalDays / 365;
                totalDays %= 365;
                int months = totalDays / 30;
                int days = totalDays % 30;

                return $"{years} Years : {months} Months : {days} Days : {hours} Hours : {minutes} Mins";
            }
            catch
            {
                return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins";
            }
        }

        #region Static Credential Helpers

        /// <summary>
        /// Get the directory where the executable is located.
        /// </summary>
        public static string GetExecutableDirectory()
        {
            string fullPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            return Path.GetDirectoryName(fullPath) + Path.DirectorySeparatorChar;
        }

        /// <summary>
        /// Save credentials for auto-login.
        /// </summary>
        public static bool SaveCredentials(int loginType, string licenseKey, string username, string password)
        {
            try
            {
                string filePath = Path.Combine(GetExecutableDirectory(), "login.json");
                var credentials = new Dictionary<string, object>
                {
                    { "loginType", loginType },
                    { "licenseKey", licenseKey ?? "" },
                    { "username", username ?? "" },
                    { "password", password ?? "" }
                };
                File.WriteAllText(filePath, jsonSerializer.Serialize(credentials));
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Load saved credentials.
        /// </summary>
        public static SavedCredentials LoadCredentials()
        {
            var creds = new SavedCredentials();

            try
            {
                string filePath = Path.Combine(GetExecutableDirectory(), "login.json");
                if (!File.Exists(filePath))
                    return creds;

                string content = File.ReadAllText(filePath);
                if (string.IsNullOrEmpty(content))
                    return creds;

                string loginTypeStr = GetJsonValueStatic(content, "loginType");
                if (!string.IsNullOrEmpty(loginTypeStr))
                    creds.LoginType = int.Parse(loginTypeStr);

                creds.LicenseKey = GetJsonValueStatic(content, "licenseKey");
                creds.Username = GetJsonValueStatic(content, "username");
                creds.Password = GetJsonValueStatic(content, "password");

                // Validate credentials
                if (creds.LoginType == 1 && !string.IsNullOrEmpty(creds.LicenseKey))
                {
                    creds.IsValid = true;
                }
                else if (creds.LoginType == 2 && !string.IsNullOrEmpty(creds.Username) && !string.IsNullOrEmpty(creds.Password))
                {
                    creds.IsValid = true;
                }
            }
            catch
            {
                // Return invalid credentials on error
            }

            return creds;
        }

        /// <summary>
        /// Delete saved credentials.
        /// </summary>
        public static bool DeleteCredentials()
        {
            try
            {
                string filePath = Path.Combine(GetExecutableDirectory(), "login.json");
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Private Helpers

        /// <summary>
        /// Generate hardware ID based on system information.
        /// </summary>
        private string GetHwid()
        {
            try
            {
                StringBuilder sb = new StringBuilder();

                // CPU ID
                try
                {
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            sb.Append(obj["ProcessorId"]?.ToString() ?? "");
                        }
                    }
                }
                catch { }

                // Volume Serial
                try
                {
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID = 'C:'"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            sb.Append(obj["VolumeSerialNumber"]?.ToString() ?? "");
                        }
                    }
                }
                catch { }

                // Computer Name
                sb.Append(Environment.MachineName);

                // BIOS Serial
                try
                {
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            sb.Append(obj["SerialNumber"]?.ToString() ?? "");
                        }
                    }
                }
                catch { }

                string raw = sb.ToString();

                // DJB2 hash for stable output
                ulong hash = 5381;
                foreach (char c in raw)
                {
                    hash = ((hash << 5) + hash) + c;
                }

                // Second pass for more entropy
                ulong hash2 = 0xDEADBEEF;
                foreach (char c in raw)
                {
                    hash2 = ((hash2 << 5) + hash2) ^ c;
                }

                return hash.ToString("X") + hash2.ToString("X");
            }
            catch
            {
                return "UNKNOWN_HWID";
            }
        }

        /// <summary>
        /// Calculate MD5 hash of the executable.
        /// </summary>
        private string GetHash()
        {
            try
            {
                string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(exePath))
                    {
                        byte[] hashBytes = md5.ComputeHash(stream);
                        return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                    }
                }
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// Send HTTP request to the API with enhanced error handling.
        /// </summary>
        private string SendRequest(string endpoint, string method, string body)
        {
            try
            {
                Console.WriteLine($"Sending request to: {m_ApiUrl + endpoint}");
                Console.WriteLine($"Request method: {method}");

                var request = new HttpRequestMessage(new HttpMethod(method), m_ApiUrl + endpoint);
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");

                if (!string.IsNullOrEmpty(m_Session.Token))
                {
                    request.Headers.Add("Authorization", "Bearer " + m_Session.Token);
                }

                var response = httpClient.SendAsync(request).Result;
                string content = response.Content.ReadAsStringAsync().Result;

                Console.WriteLine($"Response status code: {response.StatusCode}");

                // Handle HTTP status codes explicitly
                if (response.StatusCode == HttpStatusCode.Forbidden)
                {
                    // Preserve the server-provided reason when a JSON body is available
                    // (e.g. \"Application is currently disabled\", \"HWID mismatch\", \"Update required\")
                    if (!string.IsNullOrEmpty(content) && content.TrimStart().StartsWith("{"))
                    {
                        return content;
                    }
                    // Other forbidden reasons
                    else
                    {
                        return "{\"success\":false,\"message\":\"Application need update , contact the developer\"}";
                    }
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    // Preserve the server-provided reason when a JSON body is available
                    // (e.g. "Invalid password", "User not found"), so callers see accurate errors.
                    if (!string.IsNullOrEmpty(content) && content.TrimStart().StartsWith("{"))
                    {
                        return content;
                    }
                    return "{\"success\":false,\"message\":\"Unauthorized access - invalid or expired session\"}";
                }
                else if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    // Preserve the server-provided reason (e.g. \"File not found\", \"Webhook not found\")
                    if (!string.IsNullOrEmpty(content) && content.TrimStart().StartsWith("{"))
                    {
                        return content;
                    }
                    return "{\"success\":false,\"message\":\"API endpoint not found\"}";
                }
                else if ((int)response.StatusCode == 429) // Too Many Requests
                {
                    return "{\"success\":false,\"message\":\"Too many requests - please try again later\"}";
                }
                else if (response.StatusCode == HttpStatusCode.InternalServerError)
                {
                    return "{\"success\":false,\"message\":\"Internal server error\"}";
                }
                else if (response.StatusCode == HttpStatusCode.BadGateway)
                {
                    return "{\"success\":false,\"message\":\"Server gateway error\"}";
                }
                else if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
                {
                    return "{\"success\":false,\"message\":\"Service temporarily unavailable\"}";
                }
                else if (response.StatusCode == HttpStatusCode.GatewayTimeout)
                {
                    return "{\"success\":false,\"message\":\"Gateway timeout\"}";
                }

                // Handle other non-success status codes
                if (!response.IsSuccessStatusCode)
                {
                    // If content is empty, return a generic error with status code
                    if (string.IsNullOrEmpty(content))
                    {
                        return "{\"success\":false,\"message\":\"HTTP Error " + (int)response.StatusCode + "\"}";
                    }
                    // If content is not valid JSON, wrap it
                    else if (!content.TrimStart().StartsWith("{"))
                    {
                        return "{\"success\":false,\"message\":\"Server returned: " + content.Replace("\"", "\\\"").Replace("\n", "\\n") + "\"}";
                    }
                    return content;
                }

                return content;
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"HTTP request exception: {ex.Message}");
                return "{\"success\":false,\"message\":\"Network error: " + ex.Message.Replace("\"", "\\\"") + "\"}";
            }
            catch (TaskCanceledException ex)
            {
                Console.WriteLine($"Request timeout exception: {ex.Message}");
                return "{\"success\":false,\"message\":\"Request timeout - please check your connection\"}";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Request exception: {ex.Message}");
                return "{\"success\":false,\"message\":\"" + ex.Message.Replace("\"", "\\\"") + "\"}";
            }
        }

        /// <summary>
        /// Convert dictionary to JSON string.
        /// </summary>
        private string DictionaryToJson(Dictionary<string, string> dict)
        {
            return jsonSerializer.Serialize(dict);
        }

        /// <summary>
        /// Escape special characters in JSON string.
        /// </summary>
        private string EscapeJson(string str)
        {
            return str
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r")
                .Replace("\t", "\\t");
        }

        /// <summary>
        /// Extract value from JSON string by key (instance method).
        /// </summary>
        private string GetJsonValue(string json, string key)
        {
            return GetJsonValueStatic(json, key);
        }

        private bool IsBlacklistResponse(string response, string message)
        {
            if (string.Equals(GetJsonValue(response, "success"), "true", StringComparison.OrdinalIgnoreCase))
                return false;
            if (string.Equals(GetJsonValue(response, "blacklisted"), "true", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.IsNullOrEmpty(message)) return false;
            string lower = message.ToLowerInvariant();
            return lower.Contains("blacklist") || lower.Contains("blacklisted");
        }

        /// <summary>
        /// Extract value from JSON string by key (static method for credentials).
        /// </summary>
        private static string GetJsonValueStatic(string json, string key)
        {
            try
            {
                var root = jsonSerializer.DeserializeObject(json) as IDictionary<string, object>;
                if (root == null || !root.ContainsKey(key) || root[key] == null) return "";
                var value = root[key];
                if (value is string text) return text;
                if (value is bool flag) return flag ? "true" : "false";
                if (value is IFormattable formattable)
                    return formattable.ToString(null, CultureInfo.InvariantCulture);
                return Convert.ToString(value, CultureInfo.InvariantCulture) ?? "";
            }
            catch
            {
                return "";
            }
        }

        #endregion

        public List<ChatChannel> GetChannels()
        {
            if (!m_Session.IsValid) return new List<ChatChannel>();

            var body = new Dictionary<string, string>
            {
                { "token", m_Session.Token },
                { "appId", m_AppId }
            };

            string response = SendRequest("/chat/channels", "POST", DictionaryToJson(body));
            
            string success = GetJsonValue(response, "success");
            if (success == "true")
            {
                var list = ParseChannels(response);
                if (list.Count == 0)
                {
                    m_LastError = "No channels found in response. Raw response: " + response;
                }
                return list;
            }
            else
            {
                string msg = GetJsonValue(response, "message");
                m_LastError = "API Error: " + msg + " | Raw: " + response;
                return new List<ChatChannel>();
            }
        }

        public List<ChatMessage> GetMessages(string channelId)
        {
            if (!m_Session.IsValid) return new List<ChatMessage>();

            var body = new Dictionary<string, string>
            {
                { "token", m_Session.Token },
                { "appId", m_AppId },
                { "channelId", channelId }
            };

            string response = SendRequest("/chat/messages", "POST", DictionaryToJson(body));
            string message = GetJsonValue(response, "message");

            // Enhanced blacklist detection
            bool isBlacklisted = false;
            string blacklistMessage = "Your IP address has been blacklisted";

            if (!string.IsNullOrEmpty(message) &&
                (message.ToLower().Contains("blacklist") ||
                 message.ToLower().Contains("blacklisted")))
            {
                isBlacklisted = true;
                blacklistMessage = message;
            }
                else if (IsBlacklistResponse(response, message))
            {
                isBlacklisted = true;
                if (!string.IsNullOrEmpty(message))
                {
                    blacklistMessage = message;
                }
            }

            if (isBlacklisted)
            {
                m_Session.IsValid = false;
                m_LastError = blacklistMessage;
                Console.WriteLine("Blacklist detected during message retrieval: " + m_LastError);
                return new List<ChatMessage>();
            }

            if (GetJsonValue(response, "success") == "true")
            {
                return ParseMessages(response);
            }

            return new List<ChatMessage>();
        }

        public bool SendMessage(string channelId, string content)
        {
            if (!m_Session.IsValid) return false;

            var body = new Dictionary<string, string>
            {
                { "token", m_Session.Token },
                { "appId", m_AppId },
                { "channelId", channelId },
                { "content", content }
            };

            string response = SendRequest("/chat/messages", "PUT", DictionaryToJson(body));
            string message = GetJsonValue(response, "message");

            // Enhanced blacklist detection
            bool isBlacklisted = false;
            string blacklistMessage = "Your IP address has been blacklisted";

            if (!string.IsNullOrEmpty(message) &&
                (message.ToLower().Contains("blacklist") ||
                 message.ToLower().Contains("blacklisted")))
            {
                isBlacklisted = true;
                blacklistMessage = message;
            }
                else if (IsBlacklistResponse(response, message))
            {
                isBlacklisted = true;
                if (!string.IsNullOrEmpty(message))
                {
                    blacklistMessage = message;
                }
            }

            if (isBlacklisted)
            {
                m_Session.IsValid = false;
                m_LastError = blacklistMessage;
                Console.WriteLine("Blacklist detected during message sending: " + m_LastError);
                return false;
            }

            return GetJsonValue(response, "success") == "true";
        }

        private List<ChatChannel> ParseChannels(string json)
        {
            var list = new List<ChatChannel>();
            try
            {
                var root = jsonSerializer.DeserializeObject(json) as IDictionary<string, object>;
                var rawChannels = root != null && root.ContainsKey("channels") ? root["channels"] as IList : null;
                if (rawChannels == null) return list;

                foreach (var rawChannel in rawChannels)
                {
                    var channel = rawChannel as IDictionary<string, object>;
                    if (channel == null) continue;
                    int cooldownTime = 0;
                    if (channel.ContainsKey("cooldownTime") && channel["cooldownTime"] != null)
                        int.TryParse(Convert.ToString(channel["cooldownTime"], CultureInfo.InvariantCulture), out cooldownTime);

                    list.Add(new ChatChannel
                    {
                        Id = JsonObjectString(channel, "id"),
                        Name = JsonObjectString(channel, "name"),
                        CooldownUnit = JsonObjectString(channel, "cooldownUnit"),
                        CooldownTime = cooldownTime
                    });
                }
            }
            catch (Exception ex)
            {
                m_LastError = "Error parsing channels: " + ex.Message;
            }
            return list;
        }

        private List<ChatMessage> ParseMessages(string json)
        {
            var list = new List<ChatMessage>();
            try
            {
                var root = jsonSerializer.DeserializeObject(json) as IDictionary<string, object>;
                var rawMessages = root != null && root.ContainsKey("messages") ? root["messages"] as IList : null;
                if (rawMessages == null) return list;

                foreach (var rawMessage in rawMessages)
                {
                    var message = rawMessage as IDictionary<string, object>;
                    if (message == null) continue;
                    list.Add(new ChatMessage
                    {
                        Id = JsonObjectString(message, "id"),
                        Sender = JsonObjectString(message, "sender", "author"),
                        Content = JsonObjectString(message, "content", "text"),
                        TimeSent = JsonObjectString(message, "timeSent", "time_sent", "timestamp")
                    });
                }
            }
            catch (Exception ex)
            {
                m_LastError = "Error parsing messages: " + ex.Message;
            }
            return list;
        }

        private static string JsonObjectString(IDictionary<string, object> value, params string[] keys)
        {
            foreach (var key in keys)
            {
                if (value.ContainsKey(key) && value[key] != null)
                    return Convert.ToString(value[key], CultureInfo.InvariantCulture) ?? "";
            }
            return "";
        }

        private string GetJsonValueFromObject(string obj, string key)
        {
            // Try standard format "key":
            string keyPattern = "\"" + key + "\":";
            int keyIndex = obj.IndexOf(keyPattern);
            
            // Try with space "key" :
            if (keyIndex == -1)
            {
                keyPattern = "\"" + key + "\" :";
                keyIndex = obj.IndexOf(keyPattern);
            }
            
            if (keyIndex == -1) return "";

            int valueStart = keyIndex + keyPattern.Length;
            
            // Skip whitespace
            while (valueStart < obj.Length && char.IsWhiteSpace(obj[valueStart]))
            {
                valueStart++;
            }
            
            if (valueStart >= obj.Length) return "";

            if (obj[valueStart] == '"')
            {
                valueStart++;
                int valueEnd = obj.IndexOf("\"", valueStart);
                if (valueEnd == -1) return "";
                return obj.Substring(valueStart, valueEnd - valueStart);
            }
            else
            {
                int valueEnd = obj.IndexOf(",", valueStart);
                if (valueEnd == -1) valueEnd = obj.Length;
                return obj.Substring(valueStart, valueEnd - valueStart).Trim();
            }
        }

        public bool DownloadFileDirect(string fileId)
        {
            if (!m_Session.IsValid)
            {
                m_LastError = "Session is invalid";
                return false;
            }

            try
            {
                var body = new Dictionary<string, string>
                {
                    { "token", m_Session.Token },
                    { "appId", m_AppId },
                    { "fileId", fileId }
                };

                string response = SendRequest("/files/download", "POST", DictionaryToJson(body));
                string message = GetJsonValue(response, "message");

                // Enhanced blacklist detection
                bool isBlacklisted = false;
                string blacklistMessage = "Your IP address has been blacklisted";

                if (!string.IsNullOrEmpty(message) &&
                    (message.ToLower().Contains("blacklist") ||
                     message.ToLower().Contains("blacklisted")))
                {
                    isBlacklisted = true;
                    blacklistMessage = message;
                }
                else if (IsBlacklistResponse(response, message))
                {
                    isBlacklisted = true;
                    if (!string.IsNullOrEmpty(message))
                    {
                        blacklistMessage = message;
                    }
                }

                if (isBlacklisted)
                {
                    m_Session.IsValid = false;
                    m_LastError = blacklistMessage;
                    Console.WriteLine("Blacklist detected during direct file download: " + m_LastError);
                    return false;
                }

                if (GetJsonValue(response, "success") == "true")
                {
                    string url = GetJsonValue(response, "downloadUrl");
                    if (string.IsNullOrEmpty(url))
                    {
                        url = GetJsonValue(response, "url");
                    }
                    if (!string.IsNullOrEmpty(url))
                    {
                        Process.Start(url);
                        return true;
                    }
                    else
                    {
                        m_LastError = "Download URL not found in response";
                        return false;
                    }
                }
                else
                {
                    m_LastError = message ?? "Unknown error";
                    return false;
                }
            }
            catch (Exception ex)
            {
                m_LastError = ex.Message;
                return false;
            }
        }
    }

    public class ChatChannel
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string CooldownUnit { get; set; }
        public int CooldownTime { get; set; }
    }

    public class ChatMessage
    {
        public string Id { get; set; }
        public string Sender { get; set; }
        public string Content { get; set; }
        public string TimeSent { get; set; }
    }
}
