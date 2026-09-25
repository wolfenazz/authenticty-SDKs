/**
 * Authenticity TypeScript SDK — self-contained usage example.
 *
 * Replace the placeholder identifiers below with your real values from the
 * Authenticity dashboard, then run with:
 *
 *   npx tsc example.ts --target ES2020 --module commonjs --esModuleInterop
 *   node example.js
 *
 * or within a project that compiles this SDK:
 *
 *   npm run example
 */
import { Authenticity } from "./src";

// Node globals used only by the file-download check below.
declare const require: any;
declare const Buffer: any;

/** Read an environment variable or return a fallback. */
function envOr(name: string, fallback: string): string {
  const v = process.env[name];
  return v && v.length > 0 ? v : fallback;
}

async function main(): Promise<void> {
  // Configure the client. API URL MUST already end with /api/v1/client.
  const ownerId = envOr("AUTH_OWNER_ID", "your-owner-id");
  const appId = envOr("AUTH_APP_ID", "your-app-id");
  const apiUrl = envOr(
    "AUTH_API_URL",
    ""
  );
  const version = envOr("AUTH_VERSION", "1.0.0");
  const licenseKey = envOr("AUTH_LICENSE_KEY", "");

  const client = new Authenticity(ownerId, appId, apiUrl, version, licenseKey);

  console.log("HWID:", client.getHwid());
  console.log("Hash:", client.getHash());

  // Check for a newer server version before sending credentials.
  const update = await client.checkForUpdate();
  if (update?.updateRequired) {
    console.error(`Update required: ${update.currentVersion}`);
    if (update.updateLink) console.error(`Download: ${update.updateLink}`);
    return;
  }

  // Try a license-key login if a key was provided, else username/password.
  let loggedIn: boolean;
  if (licenseKey) {
    console.log("Attempting license login...");
    loggedIn = await client.login();
  } else {
    console.log("Attempting username/password login...");
    loggedIn = await client.loginWithCredentials(
      envOr("AUTH_USERNAME", "demo"),
      envOr("AUTH_PASSWORD", "demo")
    );
  }

  if (!loggedIn) {
    console.log("Login failed:", client.getLastError());
    return;
  }

  const session = client.getSession();
  const app = client.getAppData();
  console.log(`Logged in as ${session.username} (expiry: ${session.expiry})`);
  console.log(
    `Application: ${app.name} ${app.version} - ${app.status}`
  );
  console.log("Remaining:", client.getRemainingTime());

  // Heartbeat / session check.
  if (!(await client.checkSession())) {
    console.log("Heartbeat failed:", client.getLastError());
    return;
  }
  console.log("Session heartbeat OK");

  // Read a server-side variable.
  const variableValue = await client.getVariable("welcomeMessage");
  console.log(`Variable welcomeMessage = ${JSON.stringify(variableValue)}`);

  // Post a log entry and verify the API accepted it.
  if (!(await client.log("Initialized TypeScript SDK example", "info"))) {
    console.log("Log failed:", client.getLastError());
  }

  // Trigger a webhook.
  const webhookOk = await client.triggerWebhook("onStart", {
    user: session.username,
  });
  console.log(
    webhookOk
      ? "Webhook triggered"
      : "Webhook failed: " + client.getLastError()
  );

  // File download check (opt-in). Set AUTH_FILE_ID to a file ID from
  // dashboard/files, then verify the bytes land on disk and the dashboard
  // Downloads counter increments after refresh.
  const fileId = process.env.AUTH_FILE_ID ?? "";
  if (!fileId) {
    console.log("Skip file download check (set AUTH_FILE_ID to test it)");
  } else {
    try {
      const data = await client.downloadFile(fileId);
      if (data && data.byteLength > 0) {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const fs = require("fs");
        const out = `downloaded_${fileId}.bin`;
        fs.writeFileSync(out, Buffer.from(data));
        console.log(`Downloaded ${data.byteLength} bytes -> ${out} (verified)`);
      } else {
        console.log("Download failed:", client.getLastError());
      }
    } catch (err: unknown) {
      console.log("Download failed:", err instanceof Error ? err.message : err);
    }
  }

  // Chat: list channels and messages.
  const channels = await client.getChannels();
  console.log(`Channels: ${channels.length}`);
  for (const channel of channels) {
    console.log(`  - ${channel.name} (${channel.id})`);
  }

  const messages = await client.getMessages("all");
  const profile = await client.getChatProfile();
  if (profile) console.log(`Chat profile: ${profile.nickname} (${profile.avatarId})`);
  console.log(`Messages: ${messages.length}`);
  for (const m of messages) {
    console.log(`  [${m.timeSent}] ${m.sender}: ${m.content}`);
  }

  // Sending is opt-in so running this example does not publish a comment by
  // accident. Set AUTH_SEND_COMMENT=true to exercise the PUT endpoint.
  if (process.env.AUTH_SEND_COMMENT === "true" && channels[0]) {
    const sent = await client.sendMessage(channels[0].id, "Hello from the TypeScript SDK example!");
    console.log(sent ? "Comment sent" : `Comment failed: ${client.getLastError()}`);
  }

  // Save and load auto-login credentials (best-effort).
  client.saveCredentials(1, licenseKey, "", "");
  const saved = client.loadCredentials();
  console.log(`Saved credentials valid: ${saved.isValid}`);
  client.deleteCredentials();

  console.log("Example finished successfully");
}

// eslint-disable-next-line @typescript-eslint/no-floating-promises
main().catch((err: unknown) => {
  console.error("Example errored:", err);
  process.exitCode = 1;
});
