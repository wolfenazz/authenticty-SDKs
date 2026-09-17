# Authenticity C++ SDK Integration Guide
## This is BETA verstion it could have some errors ! , but it's totally FREE to use !


This comprehensive guide will walk you through integrating the Authenticity authentication system into your C++ application.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Getting Started](#getting-started)
3. [SDK Integration](#sdk-integration)
4. [Authentication Implementation](#authentication-implementation)
5. [Session Management](#session-management)
6. [Advanced Features](#advanced-features)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)
9. [Examples](#examples)

## Prerequisites

Before integrating the Authenticity SDK, ensure you have:

- **Authenticity Account**: An active Authenticity account with an application created
- **Application Credentials**: Your Owner ID, Application ID, and API URL from the dashboard
- **Development Environment**: Visual Studio 2017+ with C++17 support
- **Windows SDK**: Latest Windows SDK for WinHTTP functionality

### Getting Your Credentials

1. Log in to your Authenticity dashboard
2. Navigate to Applications → Your Application
3. Copy the following values:
   - **Owner ID**: Your account identifier
   - **Application ID**: Your specific application identifier
   - **API URL**: Usually `https://your-domain.com/api/v1/client`

## Getting Started

### Step 1: Project Setup

1. Create a new C++ project in Visual Studio or open an existing one
2. Copy the following files to your project directory:
   - `Authenticity.h`
   - `Authenticity.cpp`
   - `json.hpp` (nlohmann/json library)
   - `skStr.h` (optional, for string obfuscation)

### Step 2: Project Configuration

1. Right-click your project in Solution Explorer → Properties
2. Under Configuration Properties → C/C++ → General:
   - Add the directory containing the SDK files to "Additional Include Directories"
3. Under Configuration Properties → Linker → Input:
   - Add `winhttp.lib` to "Additional Dependencies"

### Step 3: Basic Integration

Add the SDK to your main application file:

```cpp
#include "Authenticity.h"
#include <iostream>
#include <thread>
#include <chrono>

// Your application credentials
std::string ownerId = "YOUR_OWNER_ID";
std::string appId = "YOUR_APP_ID";
std::string apiUrl = "YOUR_API_URL";
std::string version = "1.0.0";

int main() {
    // Your integration code will go here
    return 0;
}
```

## SDK Integration

### Initializing the Client

The `Authenticity::Client` class is the main interface to the authentication system:

```cpp
// For license key authentication
Authenticity::Client client(ownerId, appId, apiUrl, version, licenseKey);

// For username/password authentication (license key can be empty)
Authenticity::Client client(ownerId, appId, apiUrl, version, "");
```

### Understanding the Client Class

The `Client` class provides the following key methods:

- **Authentication**: `Login()`, `LoginWithCredentials()`, `Register()`
- **Session Management**: `CheckSession()`, `GetSession()`
- **Data Retrieval**: `GetVariable()`, `DownloadFile()`, `GetAppData()`
- **Utilities**: `Log()`, `TriggerWebhook()`, `Ban()`, `GetLastError()`

## Authentication Implementation

### Method 1: License Key Authentication

```cpp
bool AuthenticateWithLicense() {
    std::string licenseKey;
    std::cout << "Enter your license key: ";
    std::getline(std::cin, licenseKey);
    
    Authenticity::Client client(ownerId, appId, apiUrl, version, licenseKey);
    
    if (client.Login()) {
        Authenticity::Session session = client.GetSession();
        std::cout << "Welcome, " << session.username << "!" << std::endl;
        std::cout << "License expires: " << client.GetRemainingTime() << std::endl;
        return true;
    } else {
        std::cout << "Authentication failed: " << client.GetLastError() << std::endl;
        return false;
    }
}
```

### Method 2: Username/Password Authentication

```cpp
bool AuthenticateWithCredentials() {
    std::string username, password;
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);
    
    Authenticity::Client client(ownerId, appId, apiUrl, version, "");
    
    if (client.LoginWithCredentials(username, password)) {
        Authenticity::Session session = client.GetSession();
        std::cout << "Welcome back, " << session.username << "!" << std::endl;
        return true;
    } else {
        std::cout << "Authentication failed: " << client.GetLastError() << std::endl;
        return false;
    }
}
```

### Method 3: User Registration

```cpp
bool RegisterNewUser() {
    std::string username, password, licenseKey;
    
    std::cout << "Choose a username: ";
    std::getline(std::cin, username);
    std::cout << "Choose a password: ";
    std::getline(std::cin, password);
    std::cout << "Enter your license key: ";
    std::getline(std::cin, licenseKey);
    
    Authenticity::Client client(ownerId, appId, apiUrl, version, "");
    
    if (client.Register(username, password, licenseKey)) {
        std::cout << "Registration successful! You can now login." << std::endl;
        return true;
    } else {
        std::cout << "Registration failed: " << client.GetLastError() << std::endl;
        return false;
    }
}
```

## Session Management

### Implementing Session Validation

Regular session validation is crucial for security and license enforcement:

```cpp
void RunWithSessionValidation(Authenticity::Client& client) {
    std::atomic<bool> running(true);
    
    // Start session validation thread
    std::thread heartbeat([&client, &running]() {
        while (running) {
            // Wait for specified interval (default: 15 seconds)
            std::this_thread::sleep_for(std::chrono::seconds(15));
            
            if (!running) break;
            
            if (!client.CheckSession()) {
                std::string error = client.GetLastError();
                
                // Handle different error types
                if (error.find("expired") != std::string::npos) {
                    MessageBoxA(NULL, 
                        "Your license has expired. The application will now close.",
                        "License Expired", 
                        MB_OK | MB_ICONERROR);
                } else {
                    MessageBoxA(NULL, 
                        ("Session validation failed: " + error).c_str(),
                        "Authentication Error", 
                        MB_OK | MB_ICONERROR);
                }
                
                exit(0); // Terminate application
            }
        }
    });
    
    // Your main application logic here
    std::cout << "Application is running. Press Enter to exit..." << std::endl;
    std::cin.get();
    
    // Clean up
    running = false;
    if (heartbeat.joinable()) {
        heartbeat.join();
    }
}
```

### Auto-Login Implementation

Save and reuse user credentials for convenience:

```cpp
#include <fstream>
#include <json.hpp>
using json = nlohmann::json;

struct SavedCredentials {
    int loginType;          // 1 = license, 2 = username/password
    std::string licenseKey;
    std::string username;
    std::string password;
    bool isValid;
};

bool SaveCredentials(const SavedCredentials& creds) {
    json data;
    data["loginType"] = creds.loginType;
    data["licenseKey"] = creds.licenseKey;
    data["username"] = creds.username;
    data["password"] = creds.password;
    
    std::ofstream file("login.json");
    if (!file.is_open()) return false;
    
    file << data.dump(4);
    file.close();
    return true;
}

SavedCredentials LoadCredentials() {
    SavedCredentials creds = {0, "", "", "", false};
    
    std::ifstream file("login.json");
    if (!file.is_open()) return creds;
    
    try {
        json data = json::parse(file);
        creds.loginType = data.value("loginType", 0);
        creds.licenseKey = data.value("licenseKey", "");
        creds.username = data.value("username", "");
        creds.password = data.value("password", "");
        
        // Validate credentials
        if (creds.loginType == 1 && !creds.licenseKey.empty()) {
            creds.isValid = true;
        } else if (creds.loginType == 2 && !creds.username.empty() && !creds.password.empty()) {
            creds.isValid = true;
        }
    } catch (...) {
        // JSON parsing failed
    }
    
    file.close();
    return creds;
}
```

## Advanced Features

### Remote Variables

Fetch configuration values from the server:

```cpp
void LoadRemoteConfiguration(Authenticity::Client& client) {
    // Get welcome message
    std::string welcomeMsg = client.GetVariable("welcome_msg");
    if (!welcomeMsg.empty()) {
        std::cout << welcomeMsg << std::endl;
    }
    
    // Get feature flags
    std::string premiumEnabled = client.GetVariable("premium_enabled");
    if (premiumEnabled == "true") {
        // Enable premium features
        EnablePremiumFeatures();
    }
    
    // Get configuration values
    std::string maxConnections = client.GetVariable("max_connections");
    if (!maxConnections.empty()) {
        int maxConn = std::stoi(maxConnections);
        SetMaxConnections(maxConn);
    }
}
```

### File Downloads

Download files securely from the server:

```cpp
bool DownloadUpdate(Authenticity::Client& client, const std::string& fileId) {
    std::vector<unsigned char> fileData = client.DownloadFile(fileId);
    
    if (!fileData.empty()) {
        std::ofstream outFile("update.bin", std::ios::binary);
        outFile.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
        outFile.close();
        
        std::cout << "Update downloaded successfully!" << std::endl;
        return true;
    } else {
        std::cout << "Failed to download update: " << client.GetLastError() << std::endl;
        return false;
    }
}
```

### Webhook Integration

Trigger remote events:

```cpp
void NotifyUserAction(Authenticity::Client& client, const std::string& action) {
    json eventData;
    eventData["action"] = action;
    eventData["timestamp"] = std::time(nullptr);
    eventData["user"] = client.GetSession().username;
    
    if (client.TriggerWebhook("user_action", eventData.dump())) {
        std::cout << "Event logged successfully" << std::endl;
    } else {
        std::cout << "Failed to log event: " << client.GetLastError() << std::endl;
    }
}
```

### Logging

Send logs to the central dashboard:

```cpp
void LogApplicationEvent(Authenticity::Client& client, const std::string& message, const std::string& type = "info") {
    client.Log(message, type);
    
    // Example usage:
    client.Log("Application started", "info");
    client.Log("User accessed premium feature", "info");
    client.Log("Authentication failed for user: " + username, "warning");
    client.Log("Critical error occurred", "error");
}
```

## Security Best Practices

### 1. Protect Your Credentials

Never hard-code sensitive information in your executable:

```cpp
// Bad practice:
std::string apiKey = "sk-1234567890abcdef";

// Good practice - use obfuscation:
std::string apiKey = skCrypt("sk-1234567890abcdef").decrypt();
```

### 2. Validate Sessions Regularly

Always implement session validation with appropriate intervals:

```cpp
// For high-security applications: 5-10 seconds
// For standard applications: 15-30 seconds
// For low-security applications: 60+ seconds
```

### 3. Handle All Error Cases

Implement comprehensive error handling:

```cpp
bool HandleAuthenticationResult(bool success, Authenticity::Client& client) {
    if (!success) {
        std::string error = client.GetLastError();
        
        if (error.find("banned") != std::string::npos) {
            MessageBoxA(NULL, "Your account has been banned.", "Banned", MB_OK | MB_ICONERROR);
            return false;
        }
        
        if (error.find("expired") != std::string::npos) {
            MessageBoxA(NULL, "Your license has expired.", "Expired", MB_OK | MB_ICONWARNING);
            return false;
        }
        
        if (error.find("disabled") != std::string::npos) {
            MessageBoxA(NULL, "This application is currently disabled.", "Disabled", MB_OK | MB_ICONWARNING);
            return false;
        }
        
        // Generic error
        MessageBoxA(NULL, error.c_str(), "Authentication Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    return true;
}
```

### 4. Implement Anti-Tampering

Use the built-in security features:

```cpp
void CheckApplicationIntegrity(Authenticity::Client& client) {
    Authenticity::Session session = client.GetSession();
    
    // If the application hash doesn't match, ban the user
    if (!session.isValid) {
        client.Ban("Application tampering detected");
        MessageBoxA(NULL, "Application integrity check failed.", "Security Alert", MB_OK | MB_ICONERROR);
        exit(1);
    }
}
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Connection Errors

**Problem**: `Authentication failed: Check your inputs or internet connection.`

**Solutions**:
- Verify internet connectivity
- Check if the API URL is correct and accessible
- Ensure firewall allows outbound connections
- Verify SSL certificate validity for HTTPS endpoints

#### 2. Hardware ID Issues

**Problem**: `Authentication failed: Hardware ID mismatch`

**Solutions**:
- Ensure the user is using the same computer
- Check if hardware changes occurred (CPU, motherboard, etc.)
- Contact support if legitimate hardware change occurred

#### 3. License Expiration

**Problem**: `Your license has expired`

**Solutions**:
- User needs to renew their license
- Check if the system clock is correct
- Verify license expiration date in the dashboard

#### 4. Compilation Errors

**Problem**: `LNK2019: unresolved external symbol WinHttp*`

**Solutions**:
- Add `winhttp.lib` to linker dependencies
- Ensure Windows SDK is properly installed
- Check project architecture (x86 vs x64)

### Debug Mode

Enable debug output for troubleshooting:

```cpp
#ifdef _DEBUG
#define DEBUG_LOG(msg) std::cout << "[DEBUG] " << msg << std::endl
#else
#define DEBUG_LOG(msg)
#endif

// Usage:
DEBUG_LOG("Attempting authentication...");
DEBUG_LOG("API Response: " + response);
```

## Examples

### Complete Application Example

```cpp
#include "Authenticity.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <Windows.h>

class SecureApplication {
private:
    Authenticity::Client client;
    std::atomic<bool> running;
    std::thread heartbeat;
    
    std::string ownerId = "YOUR_OWNER_ID";
    std::string appId = "YOUR_APP_ID";
    std::string apiUrl = "YOUR_API_URL";
    std::string version = "1.0.0";
    
public:
    SecureApplication() : client(ownerId, appId, apiUrl, version, ""), running(false) {}
    
    ~SecureApplication() {
        Stop();
    }
    
    bool Authenticate() {
        // Try auto-login first
        SavedCredentials saved = LoadCredentials();
        if (saved.isValid) {
            if (saved.loginType == 1) {
                client = Authenticity::Client(ownerId, appId, apiUrl, version, saved.licenseKey);
                if (client.Login()) {
                    StartSessionValidation();
                    return true;
                }
            } else if (saved.loginType == 2) {
                client = Authenticity::Client(ownerId, appId, apiUrl, version, "");
                if (client.LoginWithCredentials(saved.username, saved.password)) {
                    StartSessionValidation();
                    return true;
                }
            }
        }
        
        // Fall back to manual login
        return ShowLoginDialog();
    }
    
    void Run() {
        if (!Authenticate()) {
            return;
        }
        
        // Load remote configuration
        LoadRemoteConfiguration();
        
        // Main application loop
        std::cout << "Application is running. Press Enter to exit..." << std::endl;
        std::cin.get();
        
        Stop();
    }
    
private:
    bool ShowLoginDialog() {
        std::cout << "=== Authentication ===" << std::endl;
        std::cout << "1. License Key Login" << std::endl;
        std::cout << "2. Username/Password Login" << std::endl;
        std::cout << "3. Register" << std::endl;
        std::cout << "Select option: ";
        
        int option;
        std::cin >> option;
        std::cin.ignore();
        
        switch (option) {
            case 1: return LicenseKeyLogin();
            case 2: return CredentialLogin();
            case 3: return RegisterUser();
            default: 
                std::cout << "Invalid option." << std::endl;
                return false;
        }
    }
    
    bool LicenseKeyLogin() {
        std::string licenseKey;
        std::cout << "Enter license key: ";
        std::getline(std::cin, licenseKey);
        
        client = Authenticity::Client(ownerId, appId, apiUrl, version, licenseKey);
        
        if (client.Login()) {
            SaveCredentials({1, licenseKey, "", "", true});
            StartSessionValidation();
            return true;
        }
        
        std::cout << "Login failed: " << client.GetLastError() << std::endl;
        return false;
    }
    
    bool CredentialLogin() {
        std::string username, password;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";
        std::getline(std::cin, password);
        
        client = Authenticity::Client(ownerId, appId, apiUrl, version, "");
        
        if (client.LoginWithCredentials(username, password)) {
            SaveCredentials({2, "", username, password, true});
            StartSessionValidation();
            return true;
        }
        
        std::cout << "Login failed: " << client.GetLastError() << std::endl;
        return false;
    }
    
    bool RegisterUser() {
        std::string username, password, licenseKey;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";
        std::getline(std::cin, password);
        std::cout << "License Key: ";
        std::getline(std::cin, licenseKey);
        
        client = Authenticity::Client(ownerId, appId, apiUrl, version, "");
        
        if (client.Register(username, password, licenseKey)) {
            std::cout << "Registration successful! Please login." << std::endl;
            return CredentialLogin(); // Auto-login after registration
        }
        
        std::cout << "Registration failed: " << client.GetLastError() << std::endl;
        return false;
    }
    
    void StartSessionValidation() {
        running = true;
        heartbeat = std::thread([this]() {
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(15));
                
                if (!running) break;
                
                if (!client.CheckSession()) {
                    std::string error = client.GetLastError();
                    MessageBoxA(NULL, 
                        ("Session validation failed: " + error).c_str(),
                        "Authentication Error", 
                        MB_OK | MB_ICONERROR);
                    exit(0);
                }
            }
        });
    }
    
    void Stop() {
        running = false;
        if (heartbeat.joinable()) {
            heartbeat.join();
        }
    }
    
    void LoadRemoteConfiguration() {
        std::string welcome = client.GetVariable("welcome_msg");
        if (!welcome.empty()) {
            std::cout << welcome << std::endl;
        }
        
        // Log application start
        client.Log("Application started", "info");
    }
};

int main() {
    SecureApplication app;
    app.Run();
    return 0;
}
```

This comprehensive guide should help you successfully integrate the Authenticity authentication system into your C++ application. For additional support, consult the API documentation or contact the Authenticity support team.