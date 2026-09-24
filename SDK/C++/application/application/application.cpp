// this is advnaced example , you can explore it and learn from it ! ..
// remove any non-wanted functionality and implement your own APP !  ^_^


#include "Authenticity.h"
#include "skStr.h"
#include <iostream>
#include <string>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <atomic>
#include <fstream>
#include <Windows.h>
#include <vector>
#include <iomanip>

#ifdef SendMessage
#undef SendMessage
#endif

// Configure the sample through environment variables. Never commit real
// owner IDs, application IDs, license keys, or production URLs.
std::string envOr(const char* name, const char* fallback = "") {
    const char* value = std::getenv(name);
    return value && *value ? value : fallback;
}

std::string ownerId = envOr("AUTH_OWNER_ID");
std::string appId = envOr("AUTH_APP_ID");
std::string ApiUrl = envOr("AUTH_API_URL");
std::string Version = envOr("AUTH_VERSION", "1.0.0");

int timeForCheckSession = 15;

// Function prototypes for new functionality
void ShowMainMenu(Authenticity::Client& client);
void ShowChatInterface(Authenticity::Client& client);
void ShowFileInterface(Authenticity::Client& client);
void ShowVariableInterface(Authenticity::Client& client);
void ShowWebhookInterface(Authenticity::Client& client);
void ShowUserInterface(Authenticity::Client& client);
void DisplayUserInfo(Authenticity::Client& client);
void HandleError(const std::string& context, Authenticity::Client& client);
void ClearScreen();
void PauseExecution();

// Enhanced authentication flow using Authenticity static methods
bool AuthenticateUser(Authenticity::Client& client, int& loginType, std::string& licenseKey, std::string& username, std::string& password) {
    // Check for saved credentials and attempt auto-login
    Authenticity::SavedCredentials savedCreds = Authenticity::Client::LoadCredentials();
    if (savedCreds.isValid) {
        std::cout << skCrypt("--- Authenticity Auto-Login ---").decrypt() << std::endl;
        std::cout << skCrypt("Found saved credentials. Attempting auto-login...").decrypt() << std::endl;
        
        bool success = false;
        if (savedCreds.loginType == 1) {
            // License key login
            client.SetLicenseKey(savedCreds.licenseKey);
            std::cout << skCrypt("Logging in with saved license key...").decrypt() << std::endl;
            success = client.Login();
            if (success) {
                licenseKey = savedCreds.licenseKey;
                loginType = 1;
            }
        }
        else if (savedCreds.loginType == 2) {
            // Username/password login
            std::cout << skCrypt("Logging in with saved credentials...").decrypt() << std::endl;
            success = client.LoginWithCredentials(savedCreds.username, savedCreds.password);
            if (success) {
                username = savedCreds.username;
                password = savedCreds.password;
                loginType = 2;
            }
        }
        
        if (success) {
            return true;
        }
        else {
            std::cout << skCrypt("Auto-login failed: ").decrypt() << client.GetLastError() << std::endl;
            std::cout << skCrypt("Clearing saved credentials...").decrypt() << std::endl;
            Authenticity::Client::DeleteCredentials();
            PauseExecution();
            ClearScreen();
        }
    }

    // If auto-login failed or no saved credentials, show login menu
    std::cout << skCrypt("--- Authenticity Login --- \n").decrypt() << std::endl;
    std::cout << skCrypt("--- Choose one of the auth methods ---\n").decrypt() << std::endl;
    std::cout << skCrypt("1 - Login using license key").decrypt() << std::endl;
    std::cout << skCrypt("2 - Login using username and password").decrypt() << std::endl;
    std::cout << skCrypt("3 - Register\n").decrypt() << std::endl;
    std::cout << skCrypt("Select an option: ").decrypt();

    int option;
    std::cin >> option;
    std::cin.ignore(); // Clear newline

    bool success = false;
    switch (option) {
        case 1: {
            std::cout << skCrypt("Enter license key: ").decrypt();
            std::getline(std::cin, licenseKey);
            
            client.SetLicenseKey(licenseKey);
            std::cout << skCrypt("Logging in with license key...").decrypt() << std::endl;
            success = client.Login();
            loginType = 1;
            break;
        }
        case 2: {
            std::cout << skCrypt("Enter username: ").decrypt();
            std::getline(std::cin, username);
            std::cout << skCrypt("Enter password: ").decrypt();
            std::getline(std::cin, password);

            std::cout << skCrypt("Logging in with credentials...").decrypt() << std::endl;
            success = client.LoginWithCredentials(username, password);
            loginType = 2;
            break;
        }
        case 3: {
            std::cout << skCrypt("Enter username: ").decrypt();
            std::getline(std::cin, username);
            std::cout << skCrypt("Enter password: ").decrypt();
            std::getline(std::cin, password);
            std::cout << skCrypt("Enter license activation key: ").decrypt();
            std::getline(std::cin, licenseKey);

            std::cout << skCrypt("Registering...").decrypt() << std::endl;
            if (client.Register(username, password, licenseKey)) {
                std::cout << skCrypt("Registration successful! You can now login.").decrypt() << std::endl;
                PauseExecution();
                return AuthenticateUser(client, loginType, licenseKey, username, password); // Retry login after registration
            } else {
                HandleError("Registration", client);
                return false;
            }
        }
        default:
            std::cout << skCrypt("Invalid option.").decrypt() << std::endl;
            return false;
    }

    if (success) {
        // Save credentials for auto-login next time
        if (Authenticity::Client::SaveCredentials(loginType, licenseKey, username, password)) {
            std::cout << skCrypt("Credentials saved for auto-login.").decrypt() << std::endl;
        }
        return true;
    } else {
        HandleError("Authentication", client);
        return false;
    }
}

// Enhanced heartbeat thread with better error handling
void StartHeartbeatThread(Authenticity::Client& client, std::atomic<bool>& running) {
    std::thread heartbeat([&client, &running]() {
        while (running) {
            // Wait for specified seconds
            for (int i = 0; i < timeForCheckSession && running; i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            
            if (!running) break;

            if (!client.CheckSession()) {
                std::string lastError = client.GetLastError();
                
                // Enhanced error handling for different scenarios
                if (lastError.find("license has expired") != std::string::npos ||
                    lastError.find("License has expired") != std::string::npos) {
                    
                    MessageBoxA(NULL,
                        (std::string(skCrypt("Your license has expired and the application will now close.\n\n").decrypt()) + lastError).c_str(),
                        skCrypt("Authenticity - License Expired").decrypt(),
                        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
                    exit(0);
                }
                else if (lastError.find("blacklist") != std::string::npos ||
                         lastError.find("blacklisted") != std::string::npos) {
                    MessageBoxA(NULL,
                        (std::string(skCrypt("Your access has been restricted:\n\n").decrypt()) + lastError + std::string(skCrypt("\n\nThe application will now close.").decrypt())).c_str(),
                        skCrypt("Authenticity - Access Restricted").decrypt(),
                        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
                    exit(0);
                }
                else {
                    MessageBoxA(NULL,
                        (std::string(skCrypt("Session validation failed:\n\n").decrypt()) + lastError + std::string(skCrypt("\n\nThe application will now close.").decrypt())).c_str(),
                        skCrypt("Authenticity - Session Invalid").decrypt(),
                        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
                    exit(0);
                }
            }
        }
    });
    heartbeat.detach();
}

// Chat functionality interface
void ShowChatInterface(Authenticity::Client& client) {
    while (true) {
        ClearScreen();
        std::cout << skCrypt("--- Chat Interface ---").decrypt() << std::endl;
        std::cout << skCrypt("1. View available channels").decrypt() << std::endl;
        std::cout << skCrypt("2. View messages in a channel").decrypt() << std::endl;
        std::cout << skCrypt("3. Send a message").decrypt() << std::endl;
        std::cout << skCrypt("4. Back to main menu").decrypt() << std::endl;
        std::cout << skCrypt("Select an option: ").decrypt();
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: {
                std::vector<Authenticity::ChatChannel> channels = client.GetChannels();
                if (channels.empty()) {
                    std::cout << skCrypt("No channels available or error occurred: ").decrypt() << client.GetLastError() << std::endl;
                } else {
                    std::cout << skCrypt("\n--- Available Channels ---").decrypt() << std::endl;
                    for (const auto& channel : channels) {
                        std::cout << skCrypt("ID: ").decrypt() << channel.id << skCrypt(" | Name: ").decrypt() << channel.name;
                        if (channel.cooldownTime > 0) {
                            std::cout << skCrypt(" | Cooldown: ").decrypt() << channel.cooldownTime << " " << channel.cooldownUnit;
                        }
                        std::cout << std::endl;
                    }
                }
                PauseExecution();
                break;
            }
            case 2: {
                Authenticity::ChatProfile profile;
                if (client.GetChatProfile(profile)) {
                    std::cout << "Chat profile: " << profile.nickname << " (" << profile.avatarId << ")" << std::endl;
                }
                std::cout << skCrypt("Enter channel ID: ").decrypt();
                std::string channelId;
                std::getline(std::cin, channelId);
                
                std::vector<Authenticity::ChatMessage> messages = client.GetMessages(channelId);
                if (messages.empty()) {
                    std::cout << skCrypt("No messages found or error occurred: ").decrypt() << client.GetLastError() << std::endl;
                } else {
                    std::cout << skCrypt("\n--- Messages in Channel ").decrypt() << channelId << skCrypt(" ---").decrypt() << std::endl;
                    for (const auto& message : messages) {
                        std::cout << skCrypt("[").decrypt() << message.timeSent << skCrypt("] ").decrypt()
                                 << message.sender << skCrypt(": ").decrypt() << message.content << std::endl;
                    }
                }
                PauseExecution();
                break;
            }
            case 3: {
                std::cout << skCrypt("Enter channel ID: ").decrypt();
                std::string channelId;
                std::getline(std::cin, channelId);
                
                std::cout << skCrypt("Enter your message: ").decrypt();
                std::string content;
                std::getline(std::cin, content);
                
                if (client.SendMessage(channelId, content)) {
                    std::cout << skCrypt("Message sent successfully!").decrypt() << std::endl;
                } else {
                    std::cout << skCrypt("Failed to send message: ").decrypt() << client.GetLastError() << std::endl;
                }
                PauseExecution();
                break;
            }
            case 4:
                return;
            default:
                std::cout << skCrypt("Invalid option.").decrypt() << std::endl;
                PauseExecution();
                break;
        }
    }
}

// File management interface
void ShowFileInterface(Authenticity::Client& client) {
    while (true) {
        ClearScreen();
        std::cout << skCrypt("--- File Management ---").decrypt() << std::endl;
        std::cout << skCrypt("1. Download file to memory").decrypt() << std::endl;
        std::cout << skCrypt("2. Download file directly (browser)").decrypt() << std::endl;
        std::cout << skCrypt("3. Back to main menu").decrypt() << std::endl;
        std::cout << skCrypt("Select an option: ").decrypt();
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: {
                std::cout << skCrypt("Enter file ID: ").decrypt();
                std::string fileId;
                std::getline(std::cin, fileId);
                
                std::vector<unsigned char> fileData = client.DownloadFile(fileId);
                if (!fileData.empty()) {
                    std::cout << skCrypt("File downloaded successfully! Size: ").decrypt() << fileData.size() << skCrypt(" bytes").decrypt() << std::endl;
                    // Here you could save the file or process it
                } else {
                    std::cout << skCrypt("Failed to download file: ").decrypt() << client.GetLastError() << std::endl;
                }
                PauseExecution();
                break;
            }
            case 2: {
                std::cout << skCrypt("Enter file ID: ").decrypt();
                std::string fileId;
                std::getline(std::cin, fileId);
                
                if (client.DownloadFileDirect(fileId)) {
                    std::cout << skCrypt("File download initiated in browser!").decrypt() << std::endl;
                } else {
                    std::cout << skCrypt("Failed to download file: ").decrypt() << client.GetLastError() << std::endl;
                }
                PauseExecution();
                break;
            }
            case 3:
                return;
            default:
                std::cout << skCrypt("Invalid option.").decrypt() << std::endl;
                PauseExecution();
                break;
        }
    }
}

// Variable management interface
void ShowVariableInterface(Authenticity::Client& client) {
    while (true) {
        ClearScreen();
        std::cout << skCrypt("--- Variable Management ---").decrypt() << std::endl;
        std::cout << skCrypt("1. Get variable value").decrypt() << std::endl;
        std::cout << skCrypt("2. Back to main menu").decrypt() << std::endl;
        std::cout << skCrypt("Select an option: ").decrypt();
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: {
                std::cout << skCrypt("Enter variable name: ").decrypt();
                std::string varName;
                std::getline(std::cin, varName);
                
                std::string value = client.GetVariable(varName);
                if (!value.empty()) {
                    std::cout << skCrypt("Variable value: ").decrypt() << value << std::endl;
                } else {
                    std::cout << skCrypt("Variable not found or error occurred: ").decrypt() << client.GetLastError() << std::endl;
                }
                PauseExecution();
                break;
            }
            case 2:
                return;
            default:
                std::cout << skCrypt("Invalid option.").decrypt() << std::endl;
                PauseExecution();
                break;
        }
    }
}

// Webhook interface
void ShowWebhookInterface(Authenticity::Client& client) {
    while (true) {
        ClearScreen();
        std::cout << skCrypt("--- Webhook Interface ---").decrypt() << std::endl;
        std::cout << skCrypt("1. Trigger webhook").decrypt() << std::endl;
        std::cout << skCrypt("2. Back to main menu").decrypt() << std::endl;
        std::cout << skCrypt("Select an option: ").decrypt();
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: {
                std::cout << skCrypt("Enter webhook name: ").decrypt();
                std::string webhookName;
                std::getline(std::cin, webhookName);
                
                std::cout << skCrypt("Enter webhook data (JSON format): ").decrypt();
                std::string data;
                std::getline(std::cin, data);
                
                if (client.TriggerWebhook(webhookName, data)) {
                    std::cout << skCrypt("Webhook triggered successfully!").decrypt() << std::endl;
                } else {
                    std::cout << skCrypt("Failed to trigger webhook: ").decrypt() << client.GetLastError() << std::endl;
                }
                PauseExecution();
                break;
            }
            case 2:
                return;
            default:
                std::cout << skCrypt("Invalid option.").decrypt() << std::endl;
                PauseExecution();
                break;
        }
    }
}

// User interface with ban functionality
void ShowUserInterface(Authenticity::Client& client) {
    while (true) {
        ClearScreen();
        std::cout << skCrypt("--- User Management ---").decrypt() << std::endl;
        std::cout << skCrypt("1. Display user information").decrypt() << std::endl;
        std::cout << skCrypt("2. Ban current user (for testing)").decrypt() << std::endl;
        std::cout << skCrypt("3. Log an event").decrypt() << std::endl;
        std::cout << skCrypt("4. Back to main menu").decrypt() << std::endl;
        std::cout << skCrypt("Select an option: ").decrypt();
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1:
                DisplayUserInfo(client);
                PauseExecution();
                break;
            case 2: {
                std::cout << skCrypt("Enter ban reason: ").decrypt();
                std::string reason;
                std::getline(std::cin, reason);
                
                if (client.Ban(reason)) {
                    std::cout << skCrypt("User banned successfully! Application will now exit.").decrypt() << std::endl;
                    PauseExecution();
                    exit(0);
                } else {
                    std::cout << skCrypt("Failed to ban user: ").decrypt() << client.GetLastError() << std::endl;
                }
                PauseExecution();
                break;
            }
            case 3: {
                std::cout << skCrypt("Enter log message: ").decrypt();
                std::string message;
                std::getline(std::cin, message);
                
                std::cout << skCrypt("Enter log type (info/warning/error): ").decrypt();
                std::string type;
                std::getline(std::cin, type);
                
                client.Log(message, type);
                std::cout << skCrypt("Log entry created!").decrypt() << std::endl;
                PauseExecution();
                break;
            }
            case 4:
                return;
            default:
                std::cout << skCrypt("Invalid option.").decrypt() << std::endl;
                PauseExecution();
                break;
        }
    }
}

// Display comprehensive user information
void DisplayUserInfo(Authenticity::Client& client) {
    Authenticity::Session session = client.GetSession();
    Authenticity::AppData appData = client.GetAppData();
    
    std::cout << skCrypt("\n--- User Information ---") << std::endl;
    std::cout << skCrypt("Username: ") << session.username << std::endl;
    std::cout << skCrypt("IP Address: ") << session.ip << std::endl;
    std::cout << skCrypt("HWID: ") << session.hwid << std::endl;
    std::cout << skCrypt("User Level: ") << session.level << std::endl;
    std::cout << skCrypt("Session Token: ") << session.token << std::endl;
    std::cout << skCrypt("Session Expiry: ") << session.expiry << std::endl;
    std::cout << skCrypt("Remaining Time: ") << client.GetRemainingTime() << std::endl;
    
    std::cout << skCrypt("\n--- Application Information ---") << std::endl;
    std::cout << skCrypt("App Name: ") << appData.name << std::endl;
    std::cout << skCrypt("App Version: ") << appData.version << std::endl;
    std::cout << skCrypt("App Status: ") << appData.status << std::endl;
    std::cout << skCrypt("HWID Lock: ") << (appData.hwidLock ? skCrypt("Enabled") : skCrypt("Disabled")) << std::endl;
    
    if (!session.updateLink.empty()) {
        std::cout << skCrypt("Update Link: ") << session.updateLink << std::endl;
    }
}

// Main interactive menu system
void ShowMainMenu(Authenticity::Client& client) {
    while (true) {
        ClearScreen();
        std::cout << skCrypt("--- Authenticity Main Menu ---") << std::endl;
        std::cout << skCrypt("Welcome! You are now authenticated.") << std::endl;
        std::cout << std::endl;
        std::cout << skCrypt("1. Chat System") << std::endl;
        std::cout << skCrypt("2. File Management") << std::endl;
        std::cout << skCrypt("3. Variable Management") << std::endl;
        std::cout << skCrypt("4. Webhook Interface") << std::endl;
        std::cout << skCrypt("5. User Information & Management") << std::endl;
        std::cout << skCrypt("6. Exit Application") << std::endl;
        std::cout << std::endl;
        std::cout << skCrypt("Select an option: ");
        
        int choice;
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                ShowChatInterface(client);
                break;
            case 2:
                ShowFileInterface(client);
                break;
            case 3:
                ShowVariableInterface(client);
                break;
            case 4:
                ShowWebhookInterface(client);
                break;
            case 5:
                ShowUserInterface(client);
                break;
            case 6:
                return;
            default:
                std::cout << skCrypt("Invalid option. Please try again.") << std::endl;
                PauseExecution();
                break;
        }
    }
}

// Utility functions
void ClearScreen() {
    system("cls");
}

void PauseExecution() {
    std::cout << skCrypt("\nPress Enter to continue...");
    std::cin.ignore();
    std::cin.get();
}

void HandleError(const std::string& context, Authenticity::Client& client) {
    std::string error = client.GetLastError();
    if (error.find("banned") != std::string::npos || error.find("Banned") != std::string::npos) {
        MessageBoxA(NULL, (std::string(skCrypt("Access Denied: ").decrypt()) + error).c_str(),
                   skCrypt("Authenticity - Banned").decrypt(), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    } else if (error.find("disabled") != std::string::npos || error.find("Disabled") != std::string::npos) {
        MessageBoxA(NULL, (std::string(skCrypt("Access Denied: ").decrypt()) + error).c_str(),
                   skCrypt("Authenticity - App Disabled").decrypt(), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    } else if (error.find("blacklist") != std::string::npos || error.find("blacklisted") != std::string::npos) {
        MessageBoxA(NULL, (std::string(skCrypt("Access Restricted: ").decrypt()) + error).c_str(),
                   skCrypt("Authenticity - Blacklisted").decrypt(), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    }
    std::cout << (context) << skCrypt(" failed: ").decrypt() << (error.empty() ? skCrypt("Unknown error").decrypt() : error) << std::endl;
}

// Main application function
void RunExample() {
    Authenticity::Client client(ownerId, appId, ApiUrl, Version, "");
    std::string licenseKey, username, password;
    int loginType = 0;

    // Check for a required update before sending login credentials.
    Authenticity::UpdateInfo update = client.CheckForUpdate();
    if (update.updateRequired) {
        std::cout << skCrypt("Update required: ").decrypt() << update.currentVersion << std::endl;
        if (!update.updateLink.empty()) {
            std::cout << skCrypt("Download: ").decrypt() << update.updateLink << std::endl;
        }
        return;
    }

    // Enhanced authentication using new static methods
    if (!AuthenticateUser(client, loginType, licenseKey, username, password)) {
        return;
    }

    ClearScreen();
    std::cout << skCrypt("Authentication successful!").decrypt() << std::endl;
    Sleep(1000);
    
    // Start heartbeat thread for session management
    std::atomic<bool> running(true);
    StartHeartbeatThread(client, running);
    
    // Show main menu with all new features
    ShowMainMenu(client);
    
    // Cleanup
    running = false;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

int main() {
    RunExample();
    std::cout << skCrypt("\nPress any key to exit...").decrypt();
    std::cin.get();
    return 0;
}
