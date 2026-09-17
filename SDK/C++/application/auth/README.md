# Authenticity C++ Authentication SDK

A comprehensive C++ SDK for integrating the Authenticity authentication system into your Windows applications. This SDK provides secure user authentication, license validation, session management, and remote configuration capabilities.

## Features

- **Multiple Authentication Methods**: Support for license key and username/password authentication
- **Hardware ID Lock**: Secure hardware-based authentication to prevent unauthorized access
- **Session Management**: Automatic session validation with configurable heartbeat intervals
- **License Validation**: Real-time license expiration checking with detailed time remaining
- **Remote Variables**: Fetch configuration values from the authentication server
- **File Downloads**: Securely download files from the authentication server
- **Webhook Integration**: Trigger remote webhooks for event notifications
- **Logging System**: Send application logs to the central dashboard
- **Auto-Login**: Save and reuse credentials for seamless user experience
- **Security Features**: Application hash validation, anti-tampering protection, and self-ban capabilities

## Requirements

- Windows operating system (Windows 7 or later)
- Visual Studio 2017 or later with C++17 support
- WinHTTP library (included with Windows SDK)
- Internet connection for authentication server communication

## Quick Start

1. Clone or download this repository
2. Open the `application.sln` solution in Visual Studio
3. Update the authentication credentials in `application.cpp`:
   ```cpp
   std::string ownerId = "YOUR_OWNER_ID";
   std::string appId = "YOUR_APP_ID";
   std::string ApiUrl = "YOUR_API_URL";
   std::string Version = "1.0.0";
   ```
4. Build and run the project

## Project Structure

```
SDK/C++/application/
├── application/
│   ├── Authenticity.h          # Main SDK header with class definitions
│   ├── Authenticity.cpp        # SDK implementation with all authentication logic
│   ├── application.cpp         # Example application demonstrating SDK usage
│   ├── utils.hpp              # Utility functions for JSON and authentication
│   ├── skStr.h                # String encryption library for obfuscation
│   └── json.hpp               # JSON parsing library (nlohmann/json)
├── application.sln            # Visual Studio solution file
└── application.vcxproj        # Visual Studio project file
```

## Basic Usage Example

```cpp
#include "Authenticity.h"

// Initialize the client
Authenticity::Client client(ownerId, appId, ApiUrl, Version, licenseKey);

// Login with license key
if (client.Login()) {
    std::cout << "Authentication successful!" << std::endl;
    
    // Get session information
    Authenticity::Session session = client.GetSession();
    std::cout << "Welcome, " << session.username << std::endl;
    
    // Check session periodically
    while (client.CheckSession()) {
        // Your application logic here
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
} else {
    std::cout << "Authentication failed: " << client.GetLastError() << std::endl;
}
```

## Authentication Methods

### 1. License Key Authentication
```cpp
Authenticity::Client client(ownerId, appId, apiUrl, version, licenseKey);
if (client.Login()) {
    // Success - user authenticated
}
```

### 2. Username/Password Authentication
```cpp
Authenticity::Client client(ownerId, appId, apiUrl, version, "");
if (client.LoginWithCredentials(username, password)) {
    // Success - user authenticated
}
```

### 3. User Registration
```cpp
Authenticity::Client client(ownerId, appId, apiUrl, version, "");
if (client.Register(username, password, licenseKey)) {
    // User registered successfully
}
```

## Configuration

The SDK can be configured through the following parameters in `application.cpp`:

- `ownerId`: Your Authenticity account owner ID
- `appId`: Your application ID from the dashboard
- `ApiUrl`: The API endpoint URL (usually your server URL + `/api/v1/client`)
- `Version`: Your application version string
- `timeForCheckSesson`: Session validation interval in seconds (default: 15)

## Security Features

- **Hardware ID Generation**: Creates unique identifiers based on CPU, volume serial, computer name, and BIOS
- **Application Hashing**: Calculates MD5 hash of the executable for integrity verification
- **Session Encryption**: All API communications use secure token-based authentication
- **Anti-Tampering**: Automatic self-ban if tampering is detected

## Error Handling

The SDK provides detailed error messages through the `GetLastError()` method. Common error scenarios include:

- Invalid credentials
- Expired licenses
- Banned users
- Disabled applications
- Network connectivity issues
- Hardware ID mismatches

## Dependencies

- Windows SDK (for WinHTTP)
- nlohmann/json library (included)
- Standard C++ libraries
- Windows-specific APIs (Registry, Cryptography, etc.)

## Support

For support and documentation, visit the Authenticity dashboard or contact support.

## License

This SDK is part of the Authenticity authentication system. Usage is subject to your Authenticity service agreement.