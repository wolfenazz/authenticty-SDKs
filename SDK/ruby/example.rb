# frozen_string_literal: true

# example.rb
#
# Demonstrates usage of the Authenticity Ruby client SDK.
#
# To run against a real server:
#   ruby example.rb
#
# The base URL must ALREADY end with "/api/v1/client".

$LOAD_PATH.unshift(File.expand_path('lib', __dir__))

require 'authenticity'

# --- Configure the client -----------------------------------------------------
OWNER_ID = 'YOUR_OWNER_ID'
APP_ID = 'YOUR_APP_ID'
API_URL = ENV.fetch('AUTH_API_URL', '')
APP_VERSION = '1.0.0'

client = Authenticity::Client.new(
  owner_id: OWNER_ID,
  app_id: APP_ID,
  api_url: API_URL,
  version: APP_VERSION,
  license_key: 'YOUR_LICENSE_KEY'
)

# The machine HWID is computed automatically and is deterministic.
puts "Machine HWID: #{client.hwid}"

# Check for a required update before sending login credentials.
update = client.check_for_update
if update && update['update_required']
  puts "Update required: #{update['current_version']}"
  puts "Download: #{update['update_link']}" unless update['update_link'].to_s.empty?
  exit 0
end

# --- Login --------------------------------------------------------------------
if client.login
  puts 'Login succeeded!'
  puts "  Username : #{client.session['username']}"
  puts "  IP       : #{client.session['ip']}"
  puts "  Expiry   : #{client.session['expiry']}"
  puts "  Level    : #{client.session['level']}"
  puts "  App name : #{client.app_data['name']}"
  puts "  App ver  : #{client.app_data['version']}"
  puts "  Status   : #{client.app_data['status']}"
  puts "  HWID lock: #{client.app_data['hwid_lock']}"
  puts "  Update   : #{client.get_update_link}"
  puts "  Remaining: #{client.get_remaining_time}"
else
  puts "Login failed: #{client.get_last_error}"
  exit 1
end

# --- Heartbeat / session check ------------------------------------------------
if client.check_session
  puts 'Session is valid (heartbeat ok).'
else
  puts "Session invalid: #{client.get_last_error}"
end

# --- Blacklist check ----------------------------------------------------------
if client.check_blacklist
  puts 'This machine is BLACKLISTED.'
else
  puts 'This machine is not blacklisted.'
end

# --- Vars ---------------------------------------------------------------------
value = client.get_variable('welcome_message')
puts "Variable 'welcome_message' = #{value.inspect}"

# --- Chat ---------------------------------------------------------------------
profile = client.get_chat_profile
puts "Chat profile: #{profile['nickname']} (#{profile['avatarId']})" if profile
channels = client.get_channels
puts "Channels: #{channels.map { |c| c['name'] }.inspect}"

if channels.any?
  channel_id = channels.first['id']
  messages = client.get_messages(channel_id)
  puts "Messages in '#{channels.first['name']}': #{messages.size}"

  if ENV['AUTH_SEND_COMMENT'] == 'true'
    if client.send_message(channel_id, 'Hello from the Ruby SDK example!')
      puts 'Comment sent.'
    else
      puts "Comment failed: #{client.get_last_error}"
    end
  end
end

# --- Logs ---------------------------------------------------------------------
client.log({ 'event' => 'example_runs', 'count' => 1 }, 'info')

# --- Webhooks -----------------------------------------------------------------
client.trigger_webhook('example_webhook', { 'hello' => 'world' })

puts 'Example finished.'

# --- Authentication by credentials + register ---------------------------------
# Uncomment to demonstrate the alternate flows.
#
# if client.register('newuser', 's3cret', 'SOME_LICENSE_KEY')
#   puts 'Registered OK'
# end
#
# if client.login_with_credentials('newuser', 's3cret')
#   puts 'Logged in with credentials'
# end

# --- Saved credentials ---------------------------------------------------------
# client.save_credentials('license', 'KEY', '', '')
# creds = client.load_credentials
# puts "Saved credentials valid? #{creds['is_valid']}"
