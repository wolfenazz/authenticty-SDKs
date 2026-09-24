'use strict';

/**
 * Authenticity JavaScript SDK - Example Usage
 * ============================================
 *
 * A self-contained example that demonstrates the SDK. Replace the placeholder
 * configuration with your real values and run it:
 *
 *     node example.js
 *
 * Uses only Node built-ins (global fetch) - no external dependencies.
 */

const { Authenticity, LoginTypeLicense } = require('./src/Authenticity');

// Environment variables with sensible fallbacks so the example runs anywhere.
const envOr = (name, fallback) => {
  const v = process.env[name];
  return v && v !== '' ? v : fallback;
};

const OWNER_ID = envOr('AUTH_OWNER_ID', 'your-owner-id');
const APP_ID = envOr('AUTH_APP_ID', 'your-app-id');
const API_URL = envOr('AUTH_API_URL', '');
const VERSION = envOr('AUTH_VERSION', '1.0.0');
const LICENSE_KEY = envOr('AUTH_LICENSE_KEY', '');
const USERNAME = envOr('AUTH_USERNAME', 'demo');
const PASSWORD = envOr('AUTH_PASSWORD', 'demo');

async function main() {
  const client = new Authenticity(OWNER_ID, APP_ID, API_URL, VERSION, LICENSE_KEY);
  console.log('HWID:', client.getHwid());

  // Check for a newer server version before sending credentials.
  const update = await client.checkForUpdate();
  if (update && update.updateRequired) {
    console.error('Update required:', update.currentVersion);
    if (update.updateLink) console.error('Download:', update.updateLink);
    return;
  }

  let loggedIn = false;
  if (LICENSE_KEY) {
    console.log('Attempting license-key login...');
    loggedIn = await client.login();
  } else {
    console.log('Attempting username/password login...');
    loggedIn = await client.loginWithCredentials(USERNAME, PASSWORD);
  }

  if (!loggedIn) {
    console.log('Login failed:', client.getLastError());
    return;
  }

  const session = client.getSession();
  console.log(`Logged in as ${session.username} (expiry: ${session.expiry})`);
  console.log('Remaining:', client.getRemainingTime());

  // Heartbeat / session validation.
  if (!(await client.checkSession())) {
    console.log('Heartbeat failed:', client.getLastError());
    return;
  }
  console.log('Session heartbeat OK');

  // Remote variables.
  console.log('welcomeMessage =', await client.getVariable('welcomeMessage'));

  // Log an entry and verify the API accepted it.
  if (!(await client.log('Initialized JavaScript SDK example', 'info'))) {
    console.log('Log failed:', client.getLastError());
  }

  // Webhook trigger.
  const ok = await client.triggerWebhook('onStart', { user: session.username });
  console.log('Webhook triggered:', ok, ok ? '' : client.getLastError());

  // Chat.
  const profile = await client.getChatProfile();
  if (profile) console.log('Chat profile:', profile.nickname, profile.avatarId);
  const channels = await client.getChannels();
  console.log('Channels:', channels.length);
  for (const ch of channels) {
    console.log(`  - ${ch.name} (${ch.id})`);
  }

  const messages = await client.getMessages('all');
  console.log('Messages:', messages.length);
  for (const m of messages) {
    console.log(`  [${m.timeSent}] ${m.sender}: ${m.content}`);
  }

  // Sending is opt-in so this example does not publish a comment by accident.
  if (process.env.AUTH_SEND_COMMENT === 'true' && channels[0]) {
    const sent = await client.sendMessage(channels[0].id, 'Hello from the JavaScript SDK example!');
    console.log(sent ? 'Comment sent' : `Comment failed: ${client.getLastError()}`);
  }

  // Auto-login credential persistence (best-effort).
  client.saveCredentials(LoginTypeLicense, LICENSE_KEY, '', '');
  const saved = client.loadCredentials();
  console.log('Saved credentials valid:', saved.isValid);
  client.deleteCredentials();

  console.log('Example finished successfully');
}

main().catch((err) => {
  console.error('Example failed:', err);
  process.exitCode = 1;
});
