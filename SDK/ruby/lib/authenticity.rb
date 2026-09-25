# frozen_string_literal: true

# authenticity.rb
#
# Authenticity client SDK for Ruby.
#
# A thin, dependency-free client for the Authenticity auth/licensing server.
# Uses only the Ruby standard library (net/http, json, openssl, digest, uri).
#
# The base URL is user-provided and ALREADY ends with "/api/v1/client";
# e.g. "https://authenticty.vercel.app/api/v1/client".
#
# After a successful login, a session token is stored and is sent both as an
# "Authorization: Bearer <token>" header AND inside the JSON body for every
# authenticated endpoint.
# Chat reads use POST /chat/messages; user comments use PUT /chat/messages.
# POST /app/update can be called before login to check for a newer version.

require 'net/http'
require 'net/https'
require 'uri'
require 'json'
require 'openssl'
require 'digest'
require 'socket'
require 'rbconfig'
require 'time'

# Top-level namespace matching the other Authenticity SDKs.
module Authenticity
  # A stable machine fingerprint helper. Deterministic and consistent with the
  # C#/C++/Python/Go SDKs: DJB2(5381) hashing + a second DJB2-XOR pass with the
  # seed 0xDEADBEEF, rendered as a hex string. Returns "UNKNOWN_HWID" on total
  # failure.
  module Hwid
    # Windows machine identifier via PowerShell WMI.
    def self.windows_id
      parts = []
      [
        'Get-WmiObject Win32_Processor | Select-Object -ExpandProperty ProcessorId',
        'Get-WmiObject Win32_LogicalDisk | Select-Object -First 1 -ExpandProperty VolumeSerialNumber',
        'Get-WmiObject Win32_BIOS | Select-Object -ExpandProperty SerialNumber'
      ].each do |cmd|
        begin
          out = `powershell -NoProfile -NonInteractive -Command "#{cmd}"`.to_s.strip
          parts << out unless out.empty?
        rescue StandardError
          nil
        end
      end
      return nil if parts.empty?

      parts.join('|')
    end

    # A fallback identifier based on the machine hostname (cross-platform).
    def self.fallback_id
      Socket.gethostname.to_s
    end

    # Standard DJB2 hash (XOR variant).
    def self.djb2(str)
      hash = 5381
      str.to_s.each_byte do |b|
        hash = ((hash * 33) ^ b) & 0xFFFFFFFF
      end
      hash
    end

    # Second DJB2 pass with XOR chaining seeded from 0xDEADBEEF.
    def self.djb2_xor(str)
      hash = 5381
      str.to_s.each_byte do |b|
        hash = ((hash * 33) ^ b) & 0xFFFFFFFF
        hash ^= 0xDEADBEEF
      end
      hash
    end

    # Compute the machine hardware ID as a hex string.
    def self.compute
      raw = windows_id || fallback_id
      return 'UNKNOWN_HWID' if raw.nil? || raw.empty?

      h1 = djb2(raw)
      h2 = djb2_xor(raw)
      combined = ((h1 & 0xFFFF) << 16) | (h2 & 0xFFFF)
      format('%08x', combined)
    end
  end

  # The Authenticity client.
  class Client
    # Timeout (in seconds) for network reads.
    READ_TIMEOUT = 30
    # User-Agent sent on every request.
    USER_AGENT = 'Authenticity SDK/1.0 (Ruby)'

    attr_reader :owner_id, :app_id, :api_url, :version, :hwid, :hash,
                :session, :app_data

    # @param owner_id   [String]
    # @param app_id     [String]
    # @param api_url    [String] absolute URL, already ending in "/api/v1/client"
    # @param version    [String] client/app version string
    # @param license_key [String, nil] optional, can be set later
    def initialize(owner_id:, app_id:, api_url:, version: '1.0.0', license_key: nil)
      @owner_id = owner_id.to_s
      @app_id = app_id.to_s
      @api_url = api_url.to_s.sub(%r{/+\z}, '')
      @version = version.to_s
      @license_key = license_key.to_s
      @session = {
        'token' => '',
        'expiry' => '',
        'username' => '',
        'ip' => '',
        'hwid' => '',
        'level' => 0,
        'subscription_id' => nil,
        'subscription_name' => nil,
        'features' => [],
        'limits' => {},
        'is_valid' => false,
        'update_link' => ''
      }
      @app_data = {
        'name' => '',
        'version' => '',
        'status' => '',
        'hwid_lock' => false
      }
      @hwid = Hwid.compute
      @hash = ''
      @last_error = ''
    end

    # ------------------------------------------------------------------ API URL

    def endpoint(path)
      "#{@api_url}#{path}"
    end


    # ------------------------------------------------------------ HTTP helpers

    # Perform a POST request to the given path with the given body hash.
    # Always parses the response body as JSON, even on non-2xx statuses, since
    # the API returns JSON error bodies with 4xx/5xx status codes.
    #
    # @return [Hash] parsed JSON response (possibly empty on total failure)
    def post(path, body = {})
      uri = URI.parse(endpoint(path))
      http = build_http(uri)

      headers = {
        'Content-Type' => 'application/json',
        'Accept' => 'application/json',
        'User-Agent' => USER_AGENT
      }
      headers['Authorization'] = "Bearer #{@session['token']}" unless @session['token'].to_s.empty?

      request = Net::HTTP::Post.new(uri.request_uri, headers)
      request.body = body.to_json

      begin
        response = http.request(request)
        parse_json(response.body.to_s)
      rescue StandardError => e
        @last_error = "Network error: #{e.message}"
        {}
      end
    end

    # Perform a PUT request to the given path with the given body hash.
    def put(path, body = {})
      uri = URI.parse(endpoint(path))
      http = build_http(uri)

      headers = {
        'Content-Type' => 'application/json',
        'Accept' => 'application/json',
        'User-Agent' => USER_AGENT
      }
      headers['Authorization'] = "Bearer #{@session['token']}" unless @session['token'].to_s.empty?

      request = Net::HTTP::Put.new(uri.request_uri, headers)
      request.body = body.to_json

      begin
        response = http.request(request)
        parse_json(response.body.to_s)
      rescue StandardError => e
        @last_error = "Network error: #{e.message}"
        {}
      end
    end

    # Perform a raw GET and return the response body as a String (bytes).
    # Used for file downloads. Follows up to 5 redirects (direct links often
    # 302 to storage) and rejects non-2xx statuses so error pages are never
    # mistaken for file bytes.
    def get_raw(url)
      current = url.to_s
      5.times do
        uri = URI.parse(current)
        http = build_http(uri)
        request = Net::HTTP::Get.new(uri.request_uri, 'User-Agent' => USER_AGENT)
        response = http.request(request)
        case response
        when Net::HTTPRedirection
          location = response['location'].to_s
          if location.empty?
            @last_error = "Download failed with HTTP status #{response.code}"
            return ''
          end
          current = URI.join(current, location).to_s
          next
        when Net::HTTPSuccess
          body = response.body.to_s
          if body.empty?
            @last_error = 'Download returned no data'
            return ''
          end
          @last_error = ''
          return body
        else
          @last_error = "Download failed with HTTP status #{response.code}"
          return ''
        end
      end
      @last_error = 'Download failed: too many redirects'
      ''
    rescue StandardError => e
      @last_error = "Network error: #{e.message}"
      ''
    end

    def build_http(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.read_timeout = READ_TIMEOUT
      http.open_timeout = READ_TIMEOUT
      http.use_ssl = (uri.scheme == 'https')
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?
      http

    # -------------------------------------------------------------- Auth login

    # Login with a license key (the typical flow).
    #
    # @return [Boolean] true on success; false otherwise (see #get_last_error)
    def login
      body = {
        'ownerId' => @owner_id,
        'appId' => @app_id,
        'licenseKey' => @license_key,
        'hwid' => @hwid,
        'version' => @version,
        'hash' => @hash
      }
      resp = post('/auth/login', body)

      if get_json_bool(resp, 'success')
        build_session(resp, @license_key)
      else
        @session['update_link'] = get_json_string(resp, 'updateLink')
        @last_error = get_json_string(resp, 'message')
        false
      end
    end

    # Login with username/password credentials.
    #
    # @return [Boolean] true on success
    def login_with_credentials(username, password)
      body = {
        'ownerId' => @owner_id,
        'appId' => @app_id,
        'username' => username.to_s,
        'password' => password.to_s,
        'hwid' => @hwid,
        'version' => @version,
        'hash' => @hash
      }
      resp = post('/auth/login-user', body)
      if get_json_bool(resp, 'success')
        build_session(resp, @license_key)
      else
        @session['update_link'] = get_json_string(resp, 'updateLink')
        @last_error = get_json_string(resp, 'message')
        false
      end
    end

    # Check for a server update before login.
    # @return [Hash, nil] normalized update information, or nil on failure.
    def check_for_update
      resp = post('/app/update', {
        'ownerId' => @owner_id,
        'appId' => @app_id,
        'version' => @version
      })
      unless get_json_bool(resp, 'success')
        @last_error = get_json_string(resp, 'message')
        return nil
      end
      current = get_json_string(resp, 'currentVersion')
      client = get_json_string(resp, 'clientVersion')
      {
        'update_required' => get_json_bool(resp, 'updateRequired'),
        'client_version' => client.empty? ? @version : client,
        'current_version' => current,
        'update_link' => get_json_string(resp, 'updateLink'),
        'app_name' => get_json_string(resp, 'appName'),
        'app_status' => get_json_string(resp, 'appStatus')
      }
    end

    # Register a new user account.
    #
    # @return [Boolean] true on success
    def register(username, password, license_key = @license_key)
      body = {
        'ownerId' => @owner_id,
        'appId' => @app_id,
        'username' => username.to_s,
        'password' => password.to_s,
        'licenseKey' => license_key.to_s,
        'hwid' => @hwid,
        'version' => @version,
        'hash' => @hash
      }
      resp = post('/auth/register', body)
      if get_json_bool(resp, 'success')
        true
      else
        @last_error = get_json_string(resp, 'message')
        false
      end
    end

    # Populate @session and @app_data from a successful login response.
    def build_session(resp, license_key)
      token = get_json_string(resp, 'token')
      if token.empty?
        @session['is_valid'] = false
        @session['update_link'] = get_json_string(resp, 'updateLink')
        @last_error = 'authenticity: login response did not include a session token'
        return false
      end
      @session['token'] = token
      @session['expiry'] = get_json_string(resp, 'expiry')
      @session['username'] = get_json_string(resp, 'username')
      @session['ip'] = get_json_string(resp, 'ip')
      @session['hwid'] = @hwid
      @session['level'] = get_json_int(resp, 'level')
      apply_subscription_fields(resp)
      @session['is_valid'] = true
      # login responses do not include updateLink; tolerate absence -> ""
      @session['update_link'] = get_json_string(resp, 'updateLink')
      @last_error = ''
      true

    # -------------------------------------------------------------- Heartbeat

    # Check the current session (heartbeat). On failure, may mark the session
    # invalid, and the reason may be "License expired" or "Session expired".
    #
    # @return [Boolean] true if the session is still valid
    def check_session
      body = { 'token' => @session['token'], 'appId' => @app_id, 'hwid' => @hwid }
      resp = post('/auth/check', body)

      if get_json_bool(resp, 'success')
        @session['is_valid'] = true
        apply_subscription_fields(resp)
        @last_error = ''
        true
      else
        @session['is_valid'] = false
        if get_json_bool(resp, 'expired')
          reason = get_json_string(resp, 'reason')
          reason = get_json_string(resp, 'message') if reason.empty?
          @last_error = reason.empty? ? 'Session expired' : reason
        else
          @last_error = get_json_string(resp, 'message')
        end
        false
      end
    end

    # Ask the server whether the active subscription grants a feature.
    def has_feature(feature)
      return false if feature.to_s.empty? || !@session['is_valid'] || @session['token'].empty?
      resp = post('/auth/check', {
        'token' => @session['token'], 'appId' => @app_id,
        'hwid' => @hwid, 'feature' => feature.to_s
      })
      return false unless get_json_bool(resp, 'success')
      apply_subscription_fields(resp)
      true
    end

    def apply_subscription_fields(resp)
      @session['subscription_id'] = resp['subscriptionId'] if resp.key?('subscriptionId')
      @session['subscription_name'] = resp['subscriptionName'] if resp.key?('subscriptionName')
      @session['level'] = get_json_int(resp, 'level') if resp.key?('level')
      if resp['features'].is_a?(Array)
        @session['features'] = resp['features'].select { |item| item.is_a?(String) }
      end
      if resp['limits'].is_a?(Hash)
        @session['limits'] = resp['limits'].select { |key, value| key.is_a?(String) && value.is_a?(Integer) && value >= 0 }
      end
    end

    # Check whether this machine's HWID is blacklisted.
    #
    # @return [Boolean] true if blacklisted
    def check_blacklist
      body = {
        'ownerId' => @owner_id,
        'appId' => @app_id,
        'hwid' => @hwid
      }
      resp = post('/auth/check-blacklist', body)
      # success true => NOT blacklisted => return false
      !get_json_bool(resp, 'success')
    end

    # Ban the current session with the given reason.
    #
    # @return [Boolean] true on success; invalidates the session on success
    def ban(reason)
      body = {
        'token' => @session['token'],
        'appId' => @app_id,
        'reason' => reason.to_s
      }
      resp = post('/auth/ban', body)
      if get_json_bool(resp, 'success')
        @session['is_valid'] = false
        @last_error = ''
        true
      else
        @last_error = get_json_string(resp, 'message')
        false
      end
    end

    # ---------------------------------------------------------------- Vars

    # Fetch a named variable's value.
    #
    # @return [String] the value ("" if not found / error)
    def get_variable(name)
      body = {
        'token' => @session['token'],
        'appId' => @app_id,
        'name' => name.to_s
      }
      resp = post('/vars/get', body)
      get_json_string(resp, 'value')
    end


      @app_data['name'] = get_json_string(resp, 'appName')
      @app_data['version'] = get_json_string(resp, 'appVersion')
      @app_data['status'] = get_json_string(resp, 'appStatus')
      @app_data['hwid_lock'] = get_json_bool(resp, 'hwidLock')

      @last_error = ''

    # ---------------------------------------------------------------- Files

    # Download a file by file id, returning the raw bytes as a String.
    #
    # @return [String] raw bytes; "" on failure (see #get_last_error)
    def download_file(file_id)
      if file_id.to_s.empty?
        @last_error = 'authenticity: fileId is required'
        return ''
      end
      unless @session['is_valid'] && !@session['token'].to_s.empty?
        @last_error = 'Session is invalid'
        return ''
      end
      body = {
        'token' => @session['token'],
        'appId' => @app_id,
        'fileId' => file_id.to_s
      }
      resp = post('/files/download', body)
      unless get_json_bool(resp, 'success')
        @last_error = get_json_string(resp, 'message')
        @last_error = 'Download failed' if @last_error.empty?
        return ''
      end
      url = get_json_string(resp, 'downloadUrl')
      url = get_json_string(resp, 'url') if url.empty?
      if url.empty?
        @last_error = 'Download URL not found in response'
        return ''
      end

      get_raw(url)
    end

    # Download a file by opening its download URL in the default browser.
    #
    # @return [Boolean] true if the URL was obtained and an open command issued
    def download_file_direct(file_id)
      if file_id.to_s.empty?
        @last_error = 'authenticity: fileId is required'
        return false
      end
      unless @session['is_valid'] && !@session['token'].to_s.empty?
        @last_error = 'Session is invalid'
        return false
      end
      body = {
        'token' => @session['token'],
        'appId' => @app_id,
        'fileId' => file_id.to_s
      }
      resp = post('/files/download', body)
      unless get_json_bool(resp, 'success')
        @last_error = get_json_string(resp, 'message')
        @last_error = 'Download failed' if @last_error.empty?
        return false
      end
      url = get_json_string(resp, 'downloadUrl')
      url = get_json_string(resp, 'url') if url.empty?
      if url.empty?
        @last_error = 'Download URL not found in response'
        return false
      end

      open_browser(url)
      true
    end

    # Open a URL in the platform default browser.
    def open_browser(url)
      os = RbConfig::CONFIG['host_os'].to_s.downcase
      if os =~ /mswin|mingw|cygwin/
        system('start', url)
      elsif os =~ /darwin|mac|osx/
        system('open', url)
      else
        system('xdg-open', url)
      end
    end

    # ------------------------------------------------------------ Webhooks

    # Trigger a webhook with the given name and arbitrary data payload.
    #
    # @return [Boolean] true on success
    def trigger_webhook(name, data)
      body = {
        'token' => @session['token'],
        'appId' => @app_id,
        'webhookName' => name.to_s,
        'data' => data.is_a?(String) ? data : JSON.generate(data.nil? ? {} : data)
      }
      resp = post('/webhooks/trigger', body)
      bool_result(resp)
    end

    # ---------------------------------------------------------------- Logs

    # Add a log entry.
    #
    # @return [Boolean] true on success
    def log(data, type = 'info')
      body = {
        'token' => @session['token'],
        'appId' => @app_id,
        'data' => data.is_a?(String) ? data : JSON.generate(data.nil? ? {} : data),
        'type' => type.to_s
      }
      resp = post('/logs/add', body)
      bool_result(resp)
    end

    # ----------------------------------------------------------------- Chat

    # Fetch all available chat channels.
    #
    # @return [Array<Hash>] channels with id, name, cooldown_unit, cooldown_time
    def get_channels
      body = {
        'token' => @session['token'],
        'appId' => @app_id
      }
      resp = post('/chat/channels', body)
      get_json_array(resp, 'channels').map { |c| normalize_channel(c) }
    end

    # Fetch messages for a channel (or "all").
    #
    # @return [Array<Hash>] messages
    def get_messages(channel_id = 'all')
      body = {
        'token' => @session['token'],
        'appId' => @app_id,
        'channelId' => channel_id.to_s
      }
      resp = post('/chat/messages', body)
      get_json_array(resp, 'messages').map { |m| normalize_message(m) }
    end

    # Send a message to a channel.
    #
    # @return [Boolean] true on success
    def send_message(channel_id, content)
      body = {
        'token' => @session['token'],
        'appId' => @app_id,
        'channelId' => channel_id.to_s,
        'content' => content.to_s
      }
      resp = put('/chat/messages', body)
      bool_result(resp)
    end

    # Return the current user's chat identity, or nil on failure.
    def get_chat_profile
      chat_profile_request('/chat/profile', 'POST', {})
    end

    # Update the current user's chat nickname and application avatar ID.
    def update_chat_profile(nickname, avatar_id)
      chat_profile_request('/chat/profile', 'PUT', {
        'nickname' => nickname.to_s, 'avatarId' => avatar_id.to_s
      })
    end

    def chat_profile_request(path, method, fields)
      body = { 'token' => @session['token'], 'appId' => @app_id }.merge(fields)
      resp = method == 'PUT' ? put(path, body) : post(path, body)
      unless get_json_bool(resp, 'success')
        @last_error = get_json_string(resp, 'message')
        return nil
      end
      @last_error = ''
      { 'id' => get_json_string(resp, 'profileId'),
        'nickname' => get_json_string(resp, 'nickname'),
        'avatarId' => get_json_string(resp, 'avatarId') }
    end

    # ----------------------------------------------------------------- Helpers

    def bool_result(resp)
      if get_json_bool(resp, 'success')
        @last_error = ''
        true
      else
        @last_error = get_json_string(resp, 'message')
        false
      end
    end

    def normalize_channel(c)
      {
        'id' => get_json_string(c, 'id'),
        'name' => get_json_string(c, 'name'),
        'cooldown_unit' => get_json_string(c, 'cooldownUnit'),
        'cooldown_time' => get_json_int(c, 'cooldownTime')
      }
    end

    def normalize_message(m)
      {
        'id' => get_json_string(m, 'id'),
        'channelId' => get_json_string(m, 'channelId'),
        'senderId' => get_json_string(m, 'senderId'),
        'sender' => get_json_string(m, 'sender'),
        'avatarId' => get_json_string(m, 'avatarId'),
        'content' => get_json_string(m, 'content'),
        'timeSent' => get_json_string(m, 'timeSent')
      }
    end

    # Tolerant JSON parsing that never raises.
    def parse_json(str)
      JSON.parse(str.to_s)
    rescue StandardError
      {}
    end

    # Tolerant readers returning safe defaults.
    def get_json_string(hash, key)
      v = hash[key]
      v.nil? ? '' : v.to_s
    end

    def get_json_bool(hash, key)
      v = hash[key]
      return false if v.nil?

      v == true || v.to_s.casecmp('true').zero? || v.to_i.nonzero?
    end

    def get_json_int(hash, key)
      v = hash[key]
      v.nil? ? 0 : v.to_i
    end

    def get_json_array(hash, key)
      v = hash[key]
      v.is_a?(Array) ? v : []
    end

    # ------------------------------------------------------ Setters / getters

    def set_license_key(key)
      @license_key = key.to_s
    end

    def get_license_key
      @license_key
    end

    def set_hash(value)
      @hash = value.to_s
    end

    def get_session
      @session
    end

    def get_app_data
      @app_data
    end

    def get_last_error
      @last_error
    end

    def get_update_link
      @session['update_link'] || ''
    end

    # Remaining time until license expiry, as a formatted string.
    #
    # @return [String] "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins"
    def get_remaining_time
      expiry = @session['expiry'].to_s
      return '0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins' if expiry.empty?

      # Lifetime licenses are returned by the server as the literal "Never".
      return 'Lifetime' if expiry.strip.casecmp('never').zero?

      begin
        exp = Time.parse(expiry)
      rescue StandardError
        return '0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins'
      end

      now = Time.now
      return '0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins' if exp <= now

      seconds = (exp - now).to_i
      years = seconds / (365 * 24 * 3600)
      seconds -= years * 365 * 24 * 3600
      months = seconds / (30 * 24 * 3600)
      seconds -= months * 30 * 24 * 3600
      days = seconds / (24 * 3600)
      seconds -= days * 24 * 3600
      hours = seconds / 3600
      seconds -= hours * 3600
      mins = seconds / 60

      "#{years} Years : #{months} Months : #{days} Days : #{hours} Hours : #{mins} Mins"
    end



    # -------------------------------------------------------- Saved credentials
    #
    # Credentials are stored in "login.json" next to the main script ($0).

    def credentials_path
      script = $PROGRAM_NAME.to_s
      dir = File.dirname(File.expand_path(script))
      File.join(dir, 'login.json')
    end

    def save_credentials(login_type, license_key, username, password)
      data = {
        'login_type' => login_type.to_s,
        'license_key' => license_key.to_s,
        'username' => username.to_s,
        'password' => password.to_s
      }
      File.write(credentials_path, JSON.pretty_generate(data))
      true
    rescue StandardError => e
      @last_error = "Failed to save credentials: #{e.message}"
      false
    end

    # Load saved credentials.
    #
    # @return [Hash] { login_type, license_key, username, password, is_valid }
    def load_credentials
      path = credentials_path
      result = {
        'login_type' => '',
        'license_key' => '',
        'username' => '',
        'password' => '',
        'is_valid' => false
      }
      return result unless File.exist?(path)

      parsed = parse_json(File.read(path))
      result['login_type'] = get_json_string(parsed, 'login_type')
      result['license_key'] = get_json_string(parsed, 'license_key')
      result['username'] = get_json_string(parsed, 'username')
      result['password'] = get_json_string(parsed, 'password')
      result['is_valid'] = !result['username'].empty? && !result['password'].empty?
      result
    rescue StandardError => e
      @last_error = "Failed to load credentials: #{e.message}"
      result
    end

    def delete_credentials
      path = credentials_path
      File.delete(path) if File.exist?(path)
      true
    rescue StandardError => e
      @last_error = "Failed to delete credentials: #{e.message}"
      false
    end

    # Documented constant for parity with other SDKs.
    VALID_VERSIONS = %w[1.0.0].freeze
  end
end
