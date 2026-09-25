<?php

/**
 * Authenticity PHP SDK - Example Usage
 * =====================================
 *
 * A self-contained example that demonstrates every feature of the PHP SDK.
 * Replace the placeholder values below with your real credentials and run it:
 *
 *     php example.php
 *
 * Requires the cURL extension (bundled with standard PHP distributions).
 */

require __DIR__ . '/src/Authenticity.php';

use function \getenv;

/** Read an environment variable with a fallback. */
function envOr($name, $fallback)
{
    $value = getenv($name);
    return ($value !== false && $value !== '') ? $value : $fallback;
}

$ownerId   = envOr('AUTH_OWNER_ID', 'your-owner-id');
$appId     = envOr('AUTH_APP_ID', 'your-app-id');
$apiUrl    = envOr('AUTH_API_URL', '');
$version   = envOr('AUTH_VERSION', '1.0.0');
$licenseKey = envOr('AUTH_LICENSE_KEY', '');
$username  = envOr('AUTH_USERNAME', 'demo');
$password  = envOr('AUTH_PASSWORD', 'demo');

$client = new Authenticity($ownerId, $appId, $apiUrl, $version, $licenseKey);

echo "HWID: " . $client->getHwid() . PHP_EOL;

// Check for a required update before sending login credentials.
$update = $client->checkForUpdate();
if (is_array($update) && !empty($update['updateRequired'])) {
    echo "Update required: " . ($update['currentVersion'] ?? '') . PHP_EOL;
    if (!empty($update['updateLink'])) {
        echo "Download: " . $update['updateLink'] . PHP_EOL;
    }
    exit(0);
}

// Prefer license-key login when a key is configured, otherwise use credentials.
if ($licenseKey !== '') {
    echo "Attempting license-key login..." . PHP_EOL;
    $loggedIn = $client->login();
} else {
    echo "Attempting username/password login..." . PHP_EOL;
    $loggedIn = $client->loginWithCredentials($username, $password);
}

if (!$loggedIn) {
    echo "Login failed: " . $client->getLastError() . PHP_EOL;
    exit(1);
}

$session = $client->getSession();
printf("Logged in as %s (expiry: %s)\n", $session['username'], $session['expiry']);
echo "Remaining: " . $client->getRemainingTime() . PHP_EOL;

// Heartbeat / session validation.
if (!$client->checkSession()) {
    echo "Heartbeat failed: " . $client->getLastError() . PHP_EOL;
    exit(1);
}
echo "Session heartbeat OK" . PHP_EOL;

// Remote variable.
echo "welcomeMessage = " . $client->getVariable('welcomeMessage') . PHP_EOL;

// Log an entry.
$client->log('Initialized PHP SDK example', 'info');

// Trigger a webhook.
$ok = $client->triggerWebhook('onStart', array('user' => $session['username']));
echo "Webhook triggered: " . ($ok ? 'yes' : 'no ' . $client->getLastError()) . PHP_EOL;

// Chat: list channels and messages.
$channels = $client->getChannels();
echo "Channels: " . count($channels) . PHP_EOL;
foreach ($channels as $ch) {
    echo "  - " . (isset($ch['name']) ? $ch['name'] : '?') . PHP_EOL;
}

$messages = $client->getMessages('all');
echo "Messages: " . count($messages) . PHP_EOL;
foreach ($messages as $m) {
    if (isset($m['sender'], $m['content'])) {
        echo "  [{$m['sender']}]: {$m['content']}" . PHP_EOL;
    }
}

// Sending is opt-in so the example never publishes a comment by accident.
$profile = $client->getChatProfile();
if ($profile !== null) {
    echo "Chat profile: {$profile['nickname']} ({$profile['avatarId']})" . PHP_EOL;
}
if (getenv('AUTH_SEND_COMMENT') === 'true' && !empty($channels[0]['id'])) {
    if ($client->sendMessage($channels[0]['id'], 'Hello from the PHP SDK example!')) {
        echo "Comment sent." . PHP_EOL;
    } else {
        echo "Comment failed: " . $client->getLastError() . PHP_EOL;
    }
}

// File download check (opt-in). Set AUTH_FILE_ID to a file ID from
// dashboard/files, then verify the bytes land on disk and the dashboard
// Downloads counter increments after refresh.
$fileId = getenv('AUTH_FILE_ID');
if ($fileId !== false && $fileId !== '') {
    $data = $client->downloadFile($fileId);
    if ($data !== '') {
        $out = 'downloaded_' . $fileId . '.bin';
        if (file_put_contents($out, $data) === strlen($data)) {
            echo "Downloaded " . strlen($data) . " bytes -> {$out} (verified)" . PHP_EOL;
        } else {
            echo "Download save failed: " . $client->getLastError() . PHP_EOL;
        }
    } else {
        echo "Download failed: " . $client->getLastError() . PHP_EOL;
    }
} else {
    echo "Skip file download check (set AUTH_FILE_ID to test it)" . PHP_EOL;
}

// Auto-login credential persistence (best-effort).
$client->saveCredentials(Authenticity::LOGIN_TYPE_LICENSE, $licenseKey, '', '');
$saved = $client->loadCredentials();
echo "Saved credentials valid: " . (($saved['isValid'] ?? false) ? 'yes' : 'no') . PHP_EOL;
$client->deleteCredentials();

echo "Example finished successfully" . PHP_EOL;
