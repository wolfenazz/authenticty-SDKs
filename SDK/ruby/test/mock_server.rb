# frozen_string_literal: true

# test/mock_server.rb
#
# A self-contained mock HTTP server for the Authenticity API, using only the
# Ruby standard library. It records every request (method, path, headers, body)
# and replies with canned JSON responses so the SDK can be exercised without
# contacting the real server.
#
# Run the accompanying test with:
#   ruby test/run_mock_test.rb

require 'socket'
require 'json'

module MockAuthenticityServer
  DEFAULT_RESPONSES = {
    '/api/v1/client/auth/login' => {
      'success' => true,
      'token' => 'mock-token-123',
      'expiry' => (Time.now + 30 * 24 * 3600).iso8601,
      'username' => 'mockuser',
      'ip' => '127.0.0.1',
      'appName' => 'MockApp',
      'appVersion' => '1.0.0',
      'appStatus' => 'active',
      'level' => 2,
      'hwidLock' => true
    },
    '/api/v1/client/auth/login-user' => {
      'success' => true,
      'token' => 'mock-token-user',
      'expiry' => (Time.now + 30 * 24 * 3600).iso8601,
      'username' => 'creduser',
      'ip' => '127.0.0.1',
      'appName' => 'MockApp',
      'appVersion' => '1.0.0',
      'appStatus' => 'active',
      'level' => 1,
      'hwidLock' => false
    },
    '/api/v1/client/auth/register' => { 'success' => true },
    '/api/v1/client/auth/check' => { 'success' => true },
    '/api/v1/client/auth/check-blacklist' => { 'success' => true },
    '/api/v1/client/auth/ban' => { 'success' => true },
    '/api/v1/client/vars/get' => { 'success' => true, 'value' => 'Hello from mock' },
    '/api/v1/client/files/download' => { 'success' => true, 'url' => '' },
    '/api/v1/client/webhooks/trigger' => { 'success' => true },
    '/api/v1/client/logs/add' => { 'success' => true },
    '/api/v1/client/chat/channels' => {
      'success' => true,
      'channels' => [
        { 'id' => 'c1', 'name' => 'general', 'cooldown_unit' => 'seconds', 'cooldown_time' => 5 }
      ]
    },
    '/api/v1/client/chat/messages' => {
      'success' => true,
      'messages' => [
        { 'id' => 'm1', 'sender' => 'alice', 'content' => 'hi', 'time_sent' => 'now' }
      ]
    }
  }.freeze

  class Server
    attr_reader :requests, :port

    def initialize(responses = DEFAULT_RESPONSES)
      @responses = {}
      responses.each { |k, v| @responses[k] = (v.is_a?(Hash) ? v.dup : v) }
      @requests = []
      @server = TCPServer.new('127.0.0.1', 0)
      @port = @server.addr[1]
      @thread = nil
    end

    # Override (or add) a canned response for a path.
    def set_response(path, response)
      @responses[path] = response
    end

    def start
      @thread = Thread.new { loop { handle(@server.accept) } }
      self
    end

    def stop
      @thread&.kill
      @server.close rescue nil
    end

    # The base URL the SDK should use (already ending with /api/v1/client).
    def api_url
      "http://127.0.0.1:#{@port}/api/v1/client"
    end

    private

    def handle(conn)
      request_line = conn.gets
      return conn.close if request_line.nil?

      method, path = request_line.split(' ')
      headers = {}
      while (line = conn.gets)
        line = line.strip
        break if line.empty?

        k, v = line.split(':', 2)
        headers[k.strip.downcase] = v.to_s.strip
      end

      body = ''
      if headers['content-length']
        body = conn.read(headers['content-length'].to_i)
      elsif header_has_chunked?(conn)
        body = read_chunked(conn)
      end

      json = begin
        JSON.parse(body)
      rescue StandardError
        {}
      end

      @requests << { 'method' => method, 'path' => path, 'headers' => headers, 'body' => json }

      # Serve raw (non-JSON) bytes for the file-download GET step.
      if method == 'GET' && path.start_with?('/files/raw/')
        raw = 'MOCKFILE_BINARY_CONTENT_123'
        conn.write(
          "HTTP/1.1 200 OK\r\n" \
          "Content-Type: application/octet-stream\r\n" \
          "Content-Length: #{raw.bytesize}\r\n" \
          "Connection: close\r\n\r\n" \
          "#{raw}"
        )
        conn.close
        return
      end

      response = @responses[path] || { 'success' => false, 'message' => 'mock: not found' }
      payload = JSON.generate(response)
      content_type = 'application/json; charset=utf-8'
      conn.write(
        "HTTP/1.1 200 OK\r\n" \
        "Content-Type: #{content_type}\r\n" \
        "Content-Length: #{payload.bytesize}\r\n" \
        "Connection: close\r\n\r\n" \
        "#{payload}"
      )
      conn.close
    rescue StandardError => e
      begin
        conn.close
      rescue StandardError
        nil
      end
      warn "mock server error: #{e.message}"
    end

    def header_has_chunked?(conn)
      # net/http uses Content-Length, so chunked rarely appears; handled for completeness.
      false
    end

    def read_chunked(_conn)
      ''
    end
  end
end
