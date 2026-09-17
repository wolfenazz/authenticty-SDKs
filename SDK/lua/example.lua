--[[
    Authenticity Lua SDK - Example Usage

    Demonstrates every feature of the SDK. Replace the placeholder
    credentials below with your real dashboard values and run:

        lua example.lua        (or: luajit example.lua)
]]

local authenticity = require("authenticity")

-- ---------------------------------------------------------------------------
-- 1. Replace with your actual values from the dashboard.
-- ---------------------------------------------------------------------------
local OWNER_ID = ""          -- <- your owner ID
local APP_ID = ""            -- <- your application ID
local API_URL = ""           -- <- set AUTH_API_URL to your /api/v1/client URL
local VERSION = "1.0.0"
local LICENSE_KEY = ""       -- optional for license-key login

-- How often to ping the server to keep the session alive (seconds).
local CHECK_INTERVAL = 15

-- ---------------------------------------------------------------------------
-- 2. Create the client.
-- ---------------------------------------------------------------------------
local client = authenticity.Client.new(OWNER_ID, APP_ID, API_URL, VERSION, LICENSE_KEY)

-- Check for a required update before sending login credentials.
local update = client:checkForUpdate()
if update and update.updateRequired then
    print("Update required: " .. (update.currentVersion or ""))
    if update.updateLink and update.updateLink ~= "" then
        print("Download: " .. update.updateLink)
    end
    os.exit(0)
end

-- ---------------------------------------------------------------------------
-- 3. Authenticate.
-- ---------------------------------------------------------------------------
if client:login() then
    print("Welcome, " .. client.session.username)
    print("Application: " .. client.appData.name .. " " .. client.appData.version)
    print("Expiry: " .. client.session.expiry)
    print("Time remaining: " .. client:getRemainingTime())
else
    print("Login failed:", client:getLastError())
    os.exit(1)
end

-- ---------------------------------------------------------------------------
-- 4. Feature demo.
-- ---------------------------------------------------------------------------
print("\n--- Feature Demo ---")

-- Remote variable
local welcome = client:getVariable("welcomeMessage")
if welcome and welcome ~= "" then
    print("welcomeMessage:", welcome)
end

-- Log an event
client:log("Application started successfully", "info")

-- Chat
local channels = client:getChannels() or {}
print("Chat channels:", #channels)
for _, channel in ipairs(channels) do
    print("  -", channel.name or channel.id or "?")
    if channel.id then
        local messages = client:getMessages(channel.id) or {}
        print("    (" .. #messages .. " recent message(s))")
        if #messages > 0 then
            local last = messages[#messages]
            print("    Last:", last.sender, "->", last.content)
        end
    end
end

-- Sending is opt-in so the example never publishes a comment by accident.
if os.getenv("AUTH_SEND_COMMENT") == "true" and channels[1] and channels[1].id then
    if client:sendMessage(channels[1].id, "Hello from the Lua SDK example!") then
        print("Comment sent.")
    else
        print("Comment failed:", client:getLastError())
    end
end

-- Trigger a webhook
client:triggerWebhook("onStart", "user logged in")

print("\nHeartbeat every " .. CHECK_INTERVAL .. "s. Press Ctrl+C to stop.")
while client:checkSession() do
    -- NOTE: block for CHECK_INTERVAL seconds without spinning.
    local deadline = os.time() + CHECK_INTERVAL
    while os.time() < deadline do end
end
print("Session ended:", client:getLastError())
