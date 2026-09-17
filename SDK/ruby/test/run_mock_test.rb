# frozen_string_literal: true

# test/run_mock_test.rb
#
# Starts the mock Authenticity server and drives every SDK method, asserting
# that each hits the correct route with the correct HTTP method and JSON body.
#
# Run:  ruby test/run_mock_test.rb

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
$LOAD_PATH.unshift(File.expand_path(__dir__))

require 'authenticity'
require 'mock_server'
require 'json'

# Detail: use a custom response for /files/download that points back at the
# mock server's raw-file route so we can validate the separate GET fetch step.
server = MockAuthenticityServer::Server.new
server.start

# Re-point the download URL at the live mock server's raw-file route.
server.set_response(
  '/api/v1/client/files/download',
  'success' => true,
  'url' => "#{server.api_url.sub(%r{/api/v1/client\z}, '')}/files/raw/mockfile.bin"
)

begin
  client = Authenticity::Client.new(
    owner_id: 'owner-1',
    app_id: 'app-1',
    api_url: server.api_url,
    version: '1.0.0',
    license_key: 'lic-1'
  )

  failures = []
  check = lambda do |label, cond|
    if cond
      puts "PASS  #{label}"
    else
      failures << label
      puts "FAIL  #{label}"
    end
  end

  # --- login -----------------------------------------------------------------
  ok = client.login
  check.call('login returns true', ok == true)
  check.call('login stores token', client.session['token'] == 'mock-token-123')
  check.call('login stores username', client.session['username'] == 'mockuser')
  check.call('login app_data name', client.app_data['name'] == 'MockApp')

  # --- login_with_credentials -------------------------------------------------
  ok = client.login_with_credentials('u', 'p')
  check.call('login_with_credentials returns true', ok == true)
  check.call('login_user token stored', client.session['token'] == 'mock-token-user')

  # --- register ----------------------------------------------------------------
  ok = client.register('new', 'pass', 'lic-2')
  check.call('register returns true', ok == true)

  # --- check_session (heartbeat) ------------------------------------------------
  ok = client.check_session
  check.call('check_session returns true', ok == true)
  check.call('check_session keeps session valid', client.session['is_valid'] == true)

  # --- check_blacklist ----------------------------------------------------------
  blacklisted = client.check_blacklist # mock returns success true -> not blacklisted
  check.call('check_blacklist false (not blacklisted)', blacklisted == false)

  # --- ban ----------------------------------------------------------------------
  ok = client.ban('test reason')
  check.call('ban returns true', ok == true)
  check.call('ban invalidates session', client.session['is_valid'] == false)

  # --- get_variable ---------------------------------------------------------------
  value = client.get_variable('some-var')
  check.call('get_variable returns value', value == 'Hello from mock')

  # --- download_file ----------------------------------------------------------------
  bytes = client.download_file('f1') # mock returns a real URL -> fetch raw bytes
  check.call('download_file returns raw bytes', bytes == 'MOCKFILE_BINARY_CONTENT_123')

  # --- trigger_webhook ----------------------------------------------------------------
  ok = client.trigger_webhook('wh', { 'a' => 1 })
  check.call('trigger_webhook returns true', ok == true)

  # --- log ------------------------------------------------------------------------------
  ok = client.log('some event', 'info')
  check.call('log returns true', ok == true)

  # --- chat ------------------------------------------------------------------------------
  channels = client.get_channels
  check.call('get_channels returns array', channels.is_a?(Array) && channels.size == 1)
  check.call('channel normalized fields', channels.first['id'] == 'c1' && channels.first['name'] == 'general')

  messages = client.get_messages('c1')
  check.call('get_messages returns array', messages.is_a?(Array) && messages.size == 1)
  check.call('message normalized fields', messages.first['sender'] == 'alice' && messages.first['content'] == 'hi')

  ok = client.send_message('c1', 'hello there')
  check.call('send_message returns true', ok == true)

  # --- verify recorded requests ---------------------------------------------------------
  reqs = server.requests
  check.call('12+ requests recorded', reqs.size >= 12)

  # Verify the critical route + method pairs.
  route_map = {
    '/auth/login' => 'POST',
    '/auth/login-user' => 'POST',
    '/auth/register' => 'POST',
    '/auth/check' => 'POST',
    '/auth/check-blacklist' => 'POST',
    '/auth/ban' => 'POST',
    '/vars/get' => 'POST',
    '/webhooks/trigger' => 'POST',
    '/logs/add' => 'POST',
    '/chat/channels' => 'POST',
    '/chat/messages' => 'POST'
  }

  # The LAST /chat/messages must be the PUT (send).
  put_req = reqs.reverse.find { |r| r['path'].end_with?('/chat/messages') && r['method'] == 'PUT' }
  check.call('/chat/messages used PUT for send', !put_req.nil?)

  route_map.each do |path, method|
    found = reqs.any? { |r| r['path'].end_with?(path) && r['method'] == method }
    check.call("route #{path} uses #{method}", found)
  end

  # Verify Authorization header present after login.
  auth_req = reqs.find { |r| r['path'].end_with?('/auth/check') }
  check.call('sends Bearer Authorization header', auth_req && auth_req['headers']['authorization'] == 'Bearer mock-token-user')

  # Verify token also in JSON body for authenticated endpoints.
  check.call('token present in body', auth_req && auth_req['body']['token'] == 'mock-token-user')

  # Verify User-Agent.
  check.call('sets User-Agent header', auth_req && auth_req['headers']['user-agent'] == 'Authenticity SDK/1.0 (Ruby)')

  puts "\n#{failures.empty? ? 'ALL CHECKS PASSED' : "#{failures.size} CHECK(S) FAILED: #{failures.join(', ')}"}"
  exit(failures.empty? ? 0 : 1)
ensure
  server.stop
end
