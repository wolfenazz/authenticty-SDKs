--[[
    authenticity.lua
    Authenticity client SDK for Lua.

    A thin client for the Authenticity auth/licensing server HTTP API
    exposed under '/api/v1/client'. The base URL is user-provided and
    ALREADY ends with '/api/v1/client'.

    Dependencies (all OPTIONAL, best-effort):
      * LuaSocket  (socket/http) - used when available
      * dkjson / json module     - used when available

    If LuaSocket is missing the module transparently falls back to
    spawning `curl` through io.popen (Windows ships curl these days).
    If no JSON module is present a small tolerant parser/encoder is
    bundled inside this file, so the module works with zero extra
    dependencies.

    Usage:
        local authenticity = require("authenticity")
        local client = authenticity.Client.new("ownerId", "appId",
            "https://your-domain.example/api/v1/client", "1.0.0")
        if client:login() then
            print("Logged in as " .. client.session.username)
        end
]]

local authenticity = {}

-- ===========================================================================
-- JSON helpers (used only if no json/dkjson module is available)
-- ===========================================================================

local function json_encode_string(sb, value)
    sb[#sb + 1] = '"'
    sb[#sb + 1] = value:gsub('[%z\1-\31\\"]', function(c)
        if c == '"' then return '\\"' end
        if c == "\\" then return "\\\\" end
        if c == "\n" then return "\\n" end
        if c == "\r" then return "\\r" end
        if c == "\t" then return "\\t" end
        return string.format("\\u%04x", c:byte())
    end)
    sb[#sb + 1] = '"'
end

local function json_encode_table(value, sb)
    if type(value) == "table" then
        local key_list = {}
        local is_array = true
        for k, _ in pairs(value) do
            if type(k) ~= "number" or k % 1 ~= 0 or k < 1 then
                is_array = false
            end
            key_list[#key_list + 1] = k
        end
        if is_array and #key_list > 0 then
            local numeric = {}
            for _, k in ipairs(key_list) do numeric[#numeric + 1] = k end
            table.sort(numeric)
            sb[#sb + 1] = "["
            for i, k in ipairs(numeric) do
                if i > 1 then sb[#sb + 1] = "," end
                json_encode_table(value[k], sb)
            end
            sb[#sb + 1] = "]"
        else
            local str_keys = {}
            for _, k in ipairs(key_list) do
                if type(k) == "string" then str_keys[#str_keys + 1] = k end
            end
            table.sort(str_keys)
            sb[#sb + 1] = "{"
            for i, k in ipairs(str_keys) do
                if i > 1 then sb[#sb + 1] = "," end
                json_encode_string(sb, k)
                sb[#sb + 1] = ":"
                json_encode_table(value[k], sb)
            end
            sb[#sb + 1] = "}"
        end
    elseif type(value) == "string" then
        json_encode_string(sb, value)
    elseif type(value) == "number" then
        sb[#sb + 1] = tostring(value)
    elseif type(value) == "boolean" then
        sb[#sb + 1] = value and "true" or "false"
    else
        sb[#sb + 1] = "null"
    end
end

local function json_encode(value)
    local sb = {}
    json_encode_table(value, sb)
    return table.concat(sb)
end

-- A small, tolerant JSON parser (objects / arrays / primitives).
local Parser = {}
Parser.__index = Parser

function Parser.new(str)
    local self = setmetatable({}, Parser)
    self.str = str
    self.pos = 1
    self.len = #str
    return self
end

function Parser:skip_ws()
    while self.pos <= self.len do
        local c = self.str:sub(self.pos, self.pos)
        if c == " " or c == "\t" or c == "\n" or c == "\r" then
            self.pos = self.pos + 1
        else
            break
        end
    end
end

function Parser:peek()
    return self.str:sub(self.pos, self.pos)
end

function Parser:parse_number()
    local start = self.pos
    while self.pos <= self.len do
        local c = self:peek()
        if (c >= "0" and c <= "9") or c == "." or c == "e" or c == "E"
            or c == "+" or c == "-" then
            self.pos = self.pos + 1
        else
            break
        end
    end
    return tonumber(self.str:sub(start, self.pos - 1)) or 0
end

function Parser:parse_string()
    self.pos = self.pos + 1 -- skip opening quote
    local sb = {}
    while self.pos <= self.len do
        local c = self.str:sub(self.pos, self.pos)
        if c == '"' then
            self.pos = self.pos + 1
            return table.concat(sb)
        elseif c == "\\" then
            self.pos = self.pos + 1
            local e = self.str:sub(self.pos, self.pos)
            if e == "n" then
                sb[#sb + 1] = "\n"
            elseif e == "r" then
                sb[#sb + 1] = "\r"
            elseif e == "t" then
                sb[#sb + 1] = "\t"
            elseif e == "b" then
                sb[#sb + 1] = "\b"
            elseif e == "f" then
                sb[#sb + 1] = "\f"
            elseif e == "/" then
                sb[#sb + 1] = "/"
            elseif e == "\\" then
                sb[#sb + 1] = "\\"
            elseif e == '"' then
                sb[#sb + 1] = '"'
            elseif e == "u" then
                local hex = self.str:sub(self.pos + 1, self.pos + 4)
                local code = tonumber(hex, 16) or 0
                if code < 0x80 then
                    sb[#sb + 1] = string.char(code)
                elseif code < 0x800 then
                    sb[#sb + 1] = string.char(
                        0xC0 + math.floor(code / 0x40),
                        0x80 + (code % 0x40))
                else
                    sb[#sb + 1] = string.char(
                        0xE0 + math.floor(code / 0x1000),
                        0x80 + (math.floor(code / 0x40) % 0x40),
                        0x80 + (code % 0x40))
                end
                self.pos = self.pos + 4
            else
                sb[#sb + 1] = e
            end
            self.pos = self.pos + 1
        else
            sb[#sb + 1] = c
            self.pos = self.pos + 1
        end
    end
    return table.concat(sb)
end


function Parser:parse_value()
    self:skip_ws()
    local c = self:peek()
    if c == '"' then
        return self:parse_string()
    elseif c == "{" then
        self.pos = self.pos + 1
        local obj = {}
        self:skip_ws()
        if self:peek() == "}" then self.pos = self.pos + 1 return obj end
        while true do
            self:skip_ws()
            local key = self:parse_string() or ""
            self:skip_ws()
            if self:peek() == ":" then self.pos = self.pos + 1 end
            obj[key] = self:parse_value()
            self:skip_ws()
            local d = self:peek()
            if d == "," then
                self.pos = self.pos + 1
            elseif d == "}" then
                self.pos = self.pos + 1
                break
            else
                break
            end
        end
        return obj
    elseif c == "[" then
        self.pos = self.pos + 1
        local arr = {}
        self:skip_ws()
        if self:peek() == "]" then self.pos = self.pos + 1 return arr end
        while true do
            arr[#arr + 1] = self:parse_value()
            self:skip_ws()
            local d = self:peek()
            if d == "," then
                self.pos = self.pos + 1
            elseif d == "]" then
                self.pos = self.pos + 1
                break
            else
                break
            end
        end
        return arr
    elseif c == "t" then
        self.pos = self.pos + 4
        return true
    elseif c == "f" then
        self.pos = self.pos + 5
        return false
    elseif c == "n" then
        self.pos = self.pos + 4
        return nil
    elseif c == "-" or (c >= "0" and c <= "9") then
        return self:parse_number()
    end
    return nil
end

function Parser:parse()
    self:skip_ws()
    return self:parse_value()
end

local function json_decode(str)
    if type(str) ~= "string" or str == "" then return nil end
    local ok, result = pcall(function() return Parser.new(str):parse() end)
    if ok then return result end
    return nil
end


-- ===========================================================================
-- Runtime capability detection (best-effort optional deps)
-- ===========================================================================

-- Public encode/decode helpers always exposed on the module.
authenticity.encode = json_encode
authenticity.decode = json_decode

-- Prefer a real JSON module if available; otherwise use the bundled one.
local json_mod
do
    local candidates = { "dkjson", "json" }
    for _, name in ipairs(candidates) do
        local ok, mod = pcall(require, name)
        if ok and type(mod) == "table" and mod.encode and mod.decode then
            json_mod = mod
            break
        end
    end
end

local function encode(value)
    if json_mod then return json_mod.encode(value) end
    return json_encode(value)
end

local function decode(str)
    if json_mod then
        local ok, res = pcall(json_mod.decode, str)
        if ok then return res end
        return nil
    end
    return json_decode(str)
end

-- LuaSocket detection.
local http
local ltn12
local use_luasocket = false
do
    local ok, sock = pcall(require, "socket")
    if ok and sock and sock.http then
        use_luasocket = true
        http = sock.http
        local ok2, lt = pcall(require, "ltn12")
        if ok2 then ltn12 = lt end
    end
end

-- Expose which HTTP backend is in use for diagnostics.
authenticity.http_backend = use_luasocket and "luasocket" or "curl"
authenticity.json_backend = json_mod and "module" or "bundled"

-- ---------------------------------------------------------------------------
-- Utilities
-- ---------------------------------------------------------------------------

-- DJB2 hash (unsigned 32-bit).
local function djb2(str)
    local hash = 5381
    for i = 1, #str do
        hash = (hash * 33 + str:byte(i)) % 4294967296
    end
    return hash
end

-- DJB2 variant with XOR folding against 0xDEADBEEF.
local function djb2_xor(str)
    local hash = 5381
    for i = 1, #str do
        hash = (hash * 33 + str:byte(i)) % 4294967296
    end
    hash = hash ~ 0xDEADBEEF
    if hash < 0 then hash = hash + 4294967296 end
    return hash
end

local function to_hex_8(num)
    return string.format("%08x", num % 4294967296)
end

local function detect_platform()
    if package.config:sub(1, 1) == "\\" then
        return "Windows"
    elseif package.config:sub(1, 1) == "/" then
        local f = io.popen("uname 2>/dev/null")
        if f then
            local out = f:read("*a")
            f:close()
            out = (out or ""):gsub("%s+", "")
            if out:len() > 0 then return out end
        end
        return "Unix"
    end
    return "Unknown"
end

local function run_command(cmd)
    local f = io.popen(cmd)
    if not f then return "" end
    local out = f:read("*a")
    f:close()
    return out or ""
end

local function hostname()
    local platform = detect_platform()
    local cmd = "hostname"
    if platform == "Windows" then cmd = cmd .. " 2>nul" else cmd = cmd .. " 2>/dev/null" end
    return run_command(cmd):gsub("%s+", "")
end


-- Stable machine fingerprint: (hostname + platform) hashed with DJB2(5381)
-- combined with a second DJB2-XOR(0xDEADBEEF), rendered as hex. This is
-- deterministic and consistent with the other language SDKs.
function authenticity.GetHwid()
    local platform = detect_platform()
    local hn = hostname()

    -- On Windows, enrich the fingerprint with the WMI ProcessorId when
    -- available (mirrors the C# SDK behaviour), otherwise fall back to
    -- hostname + platform.
    local fingerprint = hn .. platform
    if platform == "Windows" then
        local wmi = run_command(
            'powershell -NoProfile -Command "(Get-WmiObject Win32_Processor).ProcessorId" 2>nul')
        wmi = wmi:gsub("%s+", "")
        if wmi and wmi:len() > 0 then
            fingerprint = fingerprint .. wmi
        end
    end

    local h1 = djb2(fingerprint)
    local h2 = djb2_xor(fingerprint)
    if fingerprint == "" or fingerprint == platform then
        -- Could not gather a stable identifier; return a sentinel.
        return "UNKNOWN_HWID"
    end
    return to_hex_8(h1) .. to_hex_8(h2)
end

-- ---------------------------------------------------------------------------
-- HTTP layer
-- ---------------------------------------------------------------------------

local USER_AGENT = "Authenticity SDK/1.0 (Lua)"

-- Curl fallback: build a curl command that writes the response body to a
-- temp file and headers (status line included) to another. Returns
-- (body, status, headers_table).
local function curl_request(method, url, headers, body_string)
    local tmp_headers = os.tmpname()
    local tmp_body = os.tmpname()

    local cmd = { "curl", "-s", "-X", method, "--max-time", "30" }
    cmd[#cmd + 1] = "-H"
    cmd[#cmd + 1] = '"User-Agent: ' .. USER_AGENT .. '"'
    if headers then
        for k, v in pairs(headers) do
            cmd[#cmd + 1] = "-H"
            cmd[#cmd + 1] = '"' .. k .. ': ' .. v .. '"'
        end
    end
    cmd[#cmd + 1] = "-D"
    cmd[#cmd + 1] = '"' .. tmp_headers .. '"'
    cmd[#cmd + 1] = "-o"
    cmd[#cmd + 1] = '"' .. tmp_body .. '"'

    -- Write the body (if any) to a temp file and reference it via @file so
    -- quoting / escaping issues are avoided.
    local request_file
    if body_string then
        request_file = os.tmpname()
        local fh = io.open(request_file, "wb")
        if fh then
            fh:write(body_string)
            fh:close()
            cmd[#cmd + 1] = "--data-binary"
            cmd[#cmd + 1] = '@' .. request_file
        end
    end

    cmd[#cmd + 1] = '"' .. url .. '"'
    run_command(table.concat(cmd, " "))

    local result_body = ""
    local bf = io.open(tmp_body, "rb")
    if bf then
        result_body = bf:read("*a")
        bf:close()
    end
    os.remove(tmp_body)
    if request_file then os.remove(request_file) end

    -- Parse headers / status code.
    local status = 0
    local headers_out = {}
    local hf = io.open(tmp_headers, "rb")
    if hf then
        local htxt = hf:read("*a")
        hf:close()
        for line in (htxt .. "\n"):gmatch("([^\r\n]*)\r?\n") do
            local code = line:match("^HTTP/%S+%s+(%d+)")
            if code then
                status = tonumber(code)
            else
                local k, v = line:match("^([^:]+):%s*(.+)$")
                if k then headers_out[k:lower()] = v end
            end
        end
        os.remove(tmp_headers)
    end

    return result_body, status, headers_out
end

-- Perform a POST request with a JSON body. When `token` is non-nil it is
-- attached BOTH as an `Authorization: Bearer <token>` header. Returns
-- (body, status).
local function post_json(url, payload, token, method)
    method = method or "POST"
    local json_body = encode(payload)
    local auth_headers = {}
    if token and token ~= "" then
        auth_headers["Authorization"] = "Bearer " .. token
    end
    if use_luasocket then
        local headers = {
            ["Content-Type"] = "application/json",
            ["User-Agent"] = USER_AGENT,
            ["Content-Length"] = tostring(#json_body),
            ["Accept"] = "application/json",
        }
        for k, v in pairs(auth_headers) do headers[k] = v end
        local sink_table = {}
        local ok_body, status, _ = http.request{
            url = url,
            method = method,
            headers = headers,
            source = ltn12 and ltn12.source.string(json_body) or nil,
            sink = ltn12 and ltn12.sink.table(sink_table) or nil,
        }
        local body = ""
        if ltn12 then
            body = table.concat(sink_table)
        else
            body = ok_body or ""
        end
        return body, tonumber(status) or 0
    else
        if auth_headers["Authorization"] then
            auth_headers["Authorization"] = auth_headers["Authorization"]
        end
        return curl_request(method, url, auth_headers, json_body)
    end
end

-- Perform a GET request (used by downloadFile to fetch raw bytes from a
-- download URL). Returns (body, status).
local function get_url(url)
    if use_luasocket and ltn12 then
        local sink_table = {}
        local ok_body, status = http.request{
            url = url,
            method = "GET",
            headers = { ["User-Agent"] = USER_AGENT, ["Accept"] = "*/*" },
            sink = ltn12.sink.table(sink_table),
        }
        return table.concat(sink_table), tonumber(status) or 0
    else
        return curl_request("GET", url, { ["User-Agent"] = USER_AGENT }, nil)
    end
end



-- ===========================================================================
-- Client class
-- ===========================================================================

local Client = {}
Client.__index = Client
authenticity.Client = Client

-- How long (seconds) a session token is cached as "valid" before we ask the
-- server again during heartbeat checks.
local HEARTBEAT_INTERVAL = 60

-- Construct a new Client.
--   ownerId     - your Authenticity owner id
--   appId       - your application id
--   apiUrl      - base URL that ALREADY ends with '/api/v1/client'
--   version     - application version string (default "1.0.0")
--   licenseKey  - optional license key (can be set later)
--   hwid        - optional hardware id (defaults to GetHwid())
--   hash        - optional hash value
function Client.new(ownerId, appId, apiUrl, version, licenseKey, hwid, hash)
    local self = setmetatable({}, Client)
    self.ownerId = ownerId or ""
    self.appId = appId or ""
    self.apiUrl = tostring(apiUrl or ""):gsub("/+$", "")
    self.version = version or "1.0.0"
    self.licenseKey = licenseKey or ""
    self.hwid = hwid or authenticity.GetHwid()
    self.hash = hash or ""
    self.session = {
        token = "",
        expiry = "",
        username = "",
        ip = "",
        hwid = "",
        level = 0,
        subscriptionId = nil,
        subscriptionName = nil,
        features = {},
        limits = {},
        isValid = false,
        updateLink = "",
    }
    self.appData = {
        name = "",
        version = "",
        status = "",
        hwidLock = false,
    }
    self.lastError = nil
    self._lastCheck = 0
    return self
end

-- Convenience: a method-style constructor alias.
function Client:create(ownerId, appId, apiUrl, version, licenseKey, hwid, hash)
    return Client.new(ownerId, appId, apiUrl, version, licenseKey, hwid, hash)
end


-- Internal: POST to an endpoint with a body, attaching the session token as
-- an Authorization header. Returns a decoded JSON table (or nil on error).
local function api_request(self, endpoint, body, method, authorized)
    local token = self.session and self.session.token or ""
    if authorized == false then token = "" end
    local resp_body, _ = post_json(self.apiUrl .. endpoint, body, token, method)
    local parsed = decode(resp_body)
    if parsed == nil then
        self.lastError = "Failed to parse server response: " .. tostring(resp_body)
        return nil
    end
    return parsed
end

local function api_post(self, endpoint, body)
    return api_request(self, endpoint, body, "POST", true)
end

local function api_put(self, endpoint, body)
    return api_request(self, endpoint, body, "PUT", true)
end

-- Populate session/appData from a successful login response.
local function apply_subscription_response(self, data)
    if data.subscriptionId ~= nil then self.session.subscriptionId = data.subscriptionId end
    if data.subscriptionName ~= nil then self.session.subscriptionName = data.subscriptionName end
    if data.level ~= nil then self.session.level = tonumber(data.level) or self.session.level end
    if type(data.features) == "table" then
        self.session.features = {}
        for _, feature in ipairs(data.features) do
            if type(feature) == "string" then self.session.features[#self.session.features + 1] = feature end
        end
    end
    if type(data.limits) == "table" then
        self.session.limits = {}
        for key, value in pairs(data.limits) do
            local limit = tonumber(value)
            if type(key) == "string" and limit and limit >= 0 then self.session.limits[key] = math.floor(limit) end
        end
    end
end

local function apply_login_response(self, data)
    local token = data.token or ""
    if token == "" then
        self.session.isValid = false
        self.session.updateLink = data.updateLink or ""
        self.lastError = "authenticity: login response did not include a session token"
        return false
    end
    self.session.token = token
    self.session.expiry = data.expiry or ""
    self.session.username = data.username or ""
    self.session.ip = data.ip or ""
    self.session.hwid = self.hwid or ""
    self.session.level = tonumber(data.level) or 0
    apply_subscription_response(self, data)
    -- login responses do not include updateLink; tolerate its absence.
    self.session.updateLink = data.updateLink or ""
    self.session.isValid = true

    self.appData.name = data.appName or self.appData.name
    self.appData.version = data.appVersion or self.appData.version
    self.appData.status = data.appStatus or self.appData.status
    self.appData.hwidLock = (data.hwidLock == true
        or data.hwidLock == "true" or data.hwidLock == 1)

    self.lastError = nil
    return true
end

--- Login using the stored license key.
function Client:login()
    local body = {
        ownerId = self.ownerId,
        appId = self.appId,
        licenseKey = self.licenseKey,
        hwid = self.hwid,
        version = self.version,
        hash = self.hash,
    }
    local data = api_post(self, "/auth/login", body)
    if not data then return false end
    if data.success == true or data.success == "true" then
        return apply_login_response(self, data)
    end
    self.session.updateLink = data.updateLink or ""
    self.lastError = data.message or "Login failed"
    self.session.isValid = false
    return false
end

--- Login with username/password.
function Client:loginWithCredentials(username, password)
    local body = {
        ownerId = self.ownerId,
        appId = self.appId,
        username = username,
        password = password,
        hwid = self.hwid,
        version = self.version,
        hash = self.hash,
    }
    local data = api_post(self, "/auth/login-user", body)
    if not data then return false end
    if data.success == true or data.success == "true" then
        local ok = apply_login_response(self, data)
        if not ok then return false end
        -- Persist credentials for later use.
        self:saveCredentials("login", "", username, password)
        return true
    end
    self.session.updateLink = data.updateLink or ""
    self.lastError = data.message or "Login failed"
    self.session.isValid = false
    return false
end

--- Check for a server update before login.
function Client:checkForUpdate()
    local data = api_request(self, "/app/update", {
        ownerId = self.ownerId,
        appId = self.appId,
        version = self.version,
    }, "POST", false)
    if not data then return nil end
    if not (data.success == true or data.success == "true") then
        self.lastError = data.message or "Update check failed"
        return nil
    end
    return {
        updateRequired = data.updateRequired == true or data.updateRequired == "true",
        clientVersion = data.clientVersion or self.version,
        currentVersion = data.currentVersion or "",
        updateLink = data.updateLink or "",
        appName = data.appName or "",
        appStatus = data.appStatus or "",
    }
end

--- Register a new account.
-- Returns true if the server reported success, false otherwise.
function Client:register(username, password, licenseKey)
    local body = {
        ownerId = self.ownerId,
        appId = self.appId,
        username = username,
        password = password,
        licenseKey = licenseKey or self.licenseKey,
        hwid = self.hwid,
        version = self.version,
        hash = self.hash,
    }
    local data = api_post(self, "/auth/register", body)
    if not data then return false end
    if data.success == true or data.success == "true" then
        self.lastError = data.message
        return true
    end
    self.lastError = data.message or "Registration failed"
    return false
end


--- Heartbeat / session check. Returns true if the session is still valid.
-- Handles expired/reason responses by invalidating the local session.
function Client:checkSession()
    if not (self.session and self.session.isValid) then
        return false
    end

    -- Throttle heartbeat checks to avoid hammering the server.
    local now = os.time()
    if now - self._lastCheck < HEARTBEAT_INTERVAL then
        return self.session.isValid
    end
    self._lastCheck = now

    local data = api_post(self, "/auth/check", {
        token = self.session.token,
        appId = self.appId,
        hwid = self.hwid,
    })
    if not data then
        -- Network/parse error: keep session as-is but report false.
        return false
    end

    if data.success == true or data.success == "true" then
        self.session.isValid = true
        apply_subscription_response(self, data)
        self.lastError = nil
        return true
    end

    -- Session invalid — handle expired / reason.
    self.session.isValid = false
    if data.expired == true or data.expired == "true" then
        self.lastError = data.reason or data.message or "Session expired"
    else
        self.lastError = data.reason or data.message or "Session invalid"
    end
    return false
end

--- Ask the server whether the current subscription grants a feature.
function Client:hasFeature(feature)
    if type(feature) ~= "string" or feature == "" or not self.session.isValid then return false end
    local data = api_post(self, "/auth/check", {
        token = self.session.token, appId = self.appId, hwid = self.hwid, feature = feature,
    })
    if not data or not (data.success == true or data.success == "true") then return false end
    apply_subscription_response(self, data)
    return true
end

--- Check whether this machine (hwid) is blacklisted.
-- Returns true if the user IS blacklisted, false otherwise.
function Client:checkBlacklist()
    local data = api_post(self, "/auth/check-blacklist", {
        ownerId = self.ownerId,
        appId = self.appId,
        hwid = self.hwid,
    })
    if not data then return false end
    if data.success == true or data.success == "true" then
        -- success true means NOT blacklisted
        return false
    end
    self.lastError = data.message or "Blacklisted"
    return true
end

--- Ban the current session/license. Invalidates the session on success.
function Client:ban(reason)
    if not (self.session and self.session.isValid) then
        self.lastError = "No active session"
        return false
    end
    local data = api_post(self, "/auth/ban", {
        token = self.session.token,
        appId = self.appId,
        reason = reason or "",
    })
    if not data then return false end
    if data.success == true or data.success == "true" then
        self.session.isValid = false
        self.lastError = nil
        return true
    end
    self.lastError = data.message or "Ban failed"
    return false
end

--- Fetch an application variable value by name. Returns its value (or nil).
function Client:getVariable(name)
    local data = api_post(self, "/vars/get", {
        token = self.session.token,
        appId = self.appId,
        name = name,
    })
    if not data then return nil end
    if (data.success == true or data.success == "true") and data.value ~= nil then
        return data.value
    end
    self.lastError = data.message or "Variable not found"
    return nil
end

--- Download a file by fileId. Returns the raw bytes as a Lua string.
function Client:downloadFile(fileId)
    local data = api_post(self, "/files/download", {
        token = self.session.token,
        appId = self.appId,
        fileId = fileId,
    })
    if not data then return nil end
    if data.success == true or data.success == "true" then
        local url = data.url or data.downloadUrl
        if not url or url == "" then
            self.lastError = "No download URL returned"
            return nil
        end
        local raw, status = get_url(url)
        if status >= 200 and status < 300 then
            return raw
        end
        self.lastError = "File download failed (HTTP " .. tostring(status) .. ")"
        return nil
    end
    self.lastError = data.message or "File download failed"
    return nil
end

--- Download a file and open it in the default browser/application.
-- Returns true if the URL was opened.
function Client:downloadFileDirect(fileId)
    local data = api_post(self, "/files/download", {
        token = self.session.token,
        appId = self.appId,
        fileId = fileId,
    })
    if not data then return false end
    if data.success == true or data.success == "true" then
        local url = data.url or data.downloadUrl
        if not url or url == "" then
            self.lastError = "No download URL returned"
            return false
        end
        local platform = detect_platform()
        local cmd
        if platform == "Windows" then
            cmd = 'start "" "' .. url .. '"'
        elseif platform == "Darwin" then
            cmd = 'open "' .. url .. '"'
        else
            cmd = 'xdg-open "' .. url .. '"'
        end
        local ok = os.execute(cmd)
        return (ok == true or ok == 0)
    end
    self.lastError = data.message or "File download failed"
    return false
end


--- Trigger a webhook by name with optional data payload.
function Client:triggerWebhook(name, data)
    local body = {
        token = self.session.token,
        appId = self.appId,
        webhookName = name,
        data = type(data) == "string" and data or json_encode(data or {}),
    }
    local resp = api_post(self, "/webhooks/trigger", body)
    if not resp then return false end
    if resp.success == true or resp.success == "true" then
        return true
    end
    self.lastError = resp.message or "Webhook failed"
    return false
end

--- Add a log entry. `type` defaults to "info".
function Client:log(data, type_)
    local body = {
        token = self.session.token,
        appId = self.appId,
        data = type(data) == "string" and data or json_encode(data or {}),
        type = type_ or "info",
    }
    local resp = api_post(self, "/logs/add", body)
    if not resp then return false end
    return (resp.success == true or resp.success == "true")
end

--- Get the list of chat channels. Returns an array of channel tables.
function Client:getChannels()
    local resp = api_post(self, "/chat/channels", {
        token = self.session.token,
        appId = self.appId,
    })
    if not resp then return {} end
    if resp.success == true or resp.success == "true" then
        return resp.channels or {}
    end
    self.lastError = resp.message or "Failed to fetch channels"
    return {}
end

--- Get chat messages for a channel (or "all"). Returns an array of messages.
function Client:getMessages(channelId)
    local resp = api_post(self, "/chat/messages", {
        token = self.session.token,
        appId = self.appId,
        channelId = channelId or "all",
    })
    if not resp then return {} end
    if resp.success == true or resp.success == "true" then
        return resp.messages or {}
    end
    self.lastError = resp.message or "Failed to fetch messages"
    return {}
end

--- Send a message to a channel. Returns true on success.
function Client:sendMessage(channelId, content)
    local resp = api_put(self, "/chat/messages", {
        token = self.session.token,
        appId = self.appId,
        channelId = channelId,
        content = content,
    })
    if not resp then return false end
    if resp.success == true or resp.success == "true" then
        return true
    end
    self.lastError = resp.message or "Failed to send message"
    return false
end

--- Return the current user's chat identity, or nil on failure.
function Client:getChatProfile()
    local resp = api_post(self, "/chat/profile", {
        token = self.session.token, appId = self.appId,
    })
    if not resp then return nil end
    if resp.success == true or resp.success == "true" then
        self.lastError = ""
        return { id = resp.profileId or "", nickname = resp.nickname or "", avatarId = resp.avatarId or "" }
    end
    self.lastError = resp.message or "Failed to fetch chat profile"
    return nil
end

--- Update the current user's chat nickname and application avatar ID.
function Client:updateChatProfile(nickname, avatarId)
    local resp = api_put(self, "/chat/profile", {
        token = self.session.token, appId = self.appId,
        nickname = nickname, avatarId = avatarId,
    })
    if not resp then return nil end
    if resp.success == true or resp.success == "true" then
        self.lastError = ""
        return { id = resp.profileId or "", nickname = resp.nickname or "", avatarId = resp.avatarId or "" }
    end
    self.lastError = resp.message or "Failed to update chat profile"
    return nil
end


-- ===========================================================================
-- Getters / helpers / credentials
-- ===========================================================================

--- Set the license key.
function Client:setLicenseKey(key)
    self.licenseKey = key or ""
end

--- Get the current session table.
function Client:getSession()
    return self.session
end

--- Get the current app data table.
function Client:getAppData()
    return self.appData
end

--- Get the last error message (or nil).
function Client:getLastError()
    return self.lastError
end

--- Get the update link from the session (may be "" if not present).
function Client:getUpdateLink()
    return self.session and self.session.updateLink or ""
end

--- Compute remaining subscription time as a human readable string, e.g.
-- "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins".
function Client:getRemainingTime()
    local function to_num(v)
        return tonumber(v) or 0
    end
    -- Lifetime licenses are returned by the server as the literal "Never".
    if self.session and self.session.expiry
        and tostring(self.session.expiry):lower() == "never" then
        return "Lifetime"
    end
    local expiry = to_num(self.session and self.session.expiry)
    local now = os.time()
    -- If expiry looks like a full timestamp (seconds) vs a date string,
    -- try to coerce it.
    if expiry == 0 and self.session and self.session.expiry ~= "" then
        local parsed = os.time{ year = tonumber(self.session.expiry:sub(1, 4)),
            month = tonumber(self.session.expiry:sub(6, 7)),
            day = tonumber(self.session.expiry:sub(9, 10)),
            hour = tonumber(self.session.expiry:sub(12, 13)) or 0,
            min = tonumber(self.session.expiry:sub(15, 16)) or 0,
            sec = tonumber(self.session.expiry:sub(18, 19)) or 0 }
        if parsed and parsed > 0 then expiry = parsed end
    end

    local diff = expiry - now
    if diff < 0 then diff = 0 end

    local years = math.floor(diff / (365 * 24 * 3600))
    diff = diff % (365 * 24 * 3600)
    local months = math.floor(diff / (30 * 24 * 3600))
    diff = diff % (30 * 24 * 3600)
    local days = math.floor(diff / (24 * 3600))
    diff = diff % (24 * 3600)
    local hours = math.floor(diff / 3600)
    diff = diff % 3600
    local mins = math.floor(diff / 60)

    return string.format("%d Years : %d Months : %d Days : %d Hours : %d Mins",
        years, months, days, hours, mins)
end

--- Path to the credentials file (login.json) next to this script.
function Client:credentialsPath()
    local script = (debug and debug.getinfo and debug.getinfo(1, "S"))
        and debug.getinfo(1, "S").source or ""
    -- Strip "file:" or "@" prefixes and the module name.
    local dir = ""
    if script and script ~= "" then
        local p = script:gsub("^@", ""):gsub("^file:", "")
        local idx = p:match("^.*[/\\]") or p:match("^.*/") or p:match("^.*\\")
        if idx then dir = idx end
    end
    -- Fall back to the current working directory.
    if dir == "" then dir = "." .. package.config:sub(1, 1) end
    return dir .. "login.json"
end

--- Save login credentials to login.json next to this script.
function Client:saveCredentials(loginType, licenseKey, username, password)
    local normalizedType = tonumber(loginType)
    if not normalizedType then
        normalizedType = (loginType == "credentials" or loginType == "login") and 2 or 1
    end
    local savedLicense = licenseKey or ""
    local savedUsername = username or ""
    local savedPassword = password or ""
    local creds = {
        loginType = normalizedType,
        licenseKey = savedLicense,
        username = savedUsername,
        password = savedPassword,
        isValid = (normalizedType == 1 and savedLicense ~= "")
            or (normalizedType == 2 and savedUsername ~= "" and savedPassword ~= ""),
    }
    local path = self:credentialsPath()
    local fh = io.open(path, "wb")
    if not fh then return false end
    fh:write(encode(creds))
    fh:close()
    return true
end

--- Load saved credentials from login.json next to this script.
-- Returns a table {loginType, licenseKey, username, password, isValid}.
-- isValis is false if no file exists.
function Client:loadCredentials()
    local path = self:credentialsPath()
    local fh = io.open(path, "rb")
    if not fh then
        return { loginType = "", licenseKey = "", username = "", password = "",
            isValid = false }
    end
    local content = fh:read("*a")
    fh:close()
    local data = decode(content)
    if not data then
        return { loginType = "", licenseKey = "", username = "", password = "",
            isValid = false }
    end
    return {
        loginType = data.loginType or "",
        licenseKey = data.licenseKey or "",
        username = data.username or "",
        password = data.password or "",
        isValid = data.isValid ~= false,
    }
end

--- Delete the saved credentials file. Returns true on success.
function Client:deleteCredentials()
    local path = self:credentialsPath()
    local fh = io.open(path, "rb")
    if fh then
        fh:close()
        return os.remove(path)
    end
    return true
end

-- ===========================================================================
-- Module return
-- ===========================================================================

return authenticity
