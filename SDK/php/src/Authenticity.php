<?php

/**
 * Authenticity PHP SDK
 * =====================
 *
 * A complete, dependency-free (no Composer packages, cURL only) PHP client for
 * the Authenticity authentication / licensing server. It mirrors the behaviour
 * and conventions of the official Go, Python, Java, C# and C++ SDKs in the same
 * repository, and exposes every endpoint of the server's /api/v1/client/* API.
 *
 * The server exposes its client HTTP API under the base URL ending in
 * /api/v1/client (for example https://your-domain.example/api/v1/client).
 *
 * Endpoints implemented (all HTTP POST unless noted):
 *     POST  /auth/login               License-key login
 *     POST  /auth/login-user          Username/password login
 *     POST  /auth/register            Register a new user with a license key
 *     POST  /auth/check               Heartbeat / session validation
 *     POST  /auth/check-blacklist     IP / HWID / user blacklist check
 *     POST  /auth/ban                 Self-ban (anti-tampering)
 *     POST  /vars/get                 Fetch a remote variable
 *     POST  /files/download           Resolve a download URL (then GET it)
 *     POST  /webhooks/trigger         Trigger a remote webhook
 *     POST  /logs/add                 Send an application log
 *     POST  /chat/channels            List chat channels
 *     POST  /chat/messages            Fetch chat messages
 *     PUT   /chat/messages            Send a user comment/message
 *     POST  /app/update               Pre-login version/update check
 *
 * Usage is identical across all supported languages:
 *
 *     $client = new Authenticity(
 *         'YOUR_OWNER_ID',
 *         'YOUR_APP_ID',
 *         'https://your-domain.example/api/v1/client',
 *         '1.0.0',
 *         'YOUR_LICENSE_KEY',   // optional default license key
 *     );
 *
 *     if ($client->login()) {
 *         $session = $client->getSession();
 *         echo "Welcome, {$session['username']}";
 *     } else {
 *         echo 'Login failed: ' . $client->getLastError();
 *     }
 */

/**
 * Authenticity client.
 *
 * @package Authenticity
 */
class Authenticity
{
    /** Login mode where a license key is used (auto-login credential type 1). */
    const LOGIN_TYPE_LICENSE = 1;

    /** Login mode where a username/password pair is used (auto-login type 2). */
    const LOGIN_TYPE_CREDENTIALS = 2;

    /** Name of the file holding saved auto-login credentials. */
    const LOGIN_JSON_FILE = 'login.json';

    /** HWID returned by generation on total failure. */
    const HWID_UNKNOWN = 'UNKNOWN_HWID';

    /** DJB2 seed used for the first HWID hash pass. */
    const DJB2_SEED = 5381;

    /** Seed used for the second DJB2-XOR HWID hash pass. */
    const DJB2_XOR_SEED = 0xDEADBEEF;

    /** HTTP request timeout in seconds. */
    const REQUEST_TIMEOUT = 30;

    /** User-Agent header sent with every request. */
    const USER_AGENT = 'Authenticity SDK/1.0 (PHP)';

    /**
     * @var string Owner identifier.
     */
    private $ownerId;

    /**
     * @var string Application identifier.
     */
    private $appId;

    /**
     * @var string Base URL already ending with /api/v1/client.
     */
    private $apiUrl;

    /**
     * @var string SDK/client version reported to the server.
     */
    private $version;

    /**
     * @var string License key used for license-key based login.
     */
    private $licenseKey;

    /**
     * @var array Current session state (see getSession()).
     */
    private $session;

    /**
     * @var array Application metadata from the last login (see getAppData()).
     */
    private $appData;

    /**
     * @var string Generated hardware ID of this machine.
     */
    private $hwid;

    /**
     * @var string Secondary machine hash (MD5 of the running script).
     */
    private $hash;

    /**
     * @var string Most recent error message, if any.
     */
    private $lastError = '';

    /**
     * Construct the Authenticity client.
     *
     * @param string $ownerId   Owner identifier from the dashboard.
     * @param string $appId     Application identifier from the dashboard.
     * @param string $apiUrl    Full API base URL, MUST already end with
     *                          /api/v1/client (e.g.
     *                          https://your-domain.example/api/v1/client).
     * @param string $version   Client/application version string.
     * @param string $licenseKey Optional default license key for license login.
     */
    public function __construct($ownerId, $appId, $apiUrl, $version, $licenseKey = '')
    {
        $this->ownerId    = (string)$ownerId;
        $this->appId      = (string)$appId;
        $this->apiUrl     = rtrim((string)$apiUrl, '/');
        $this->version    = (string)$version;
        $this->licenseKey = (string)$licenseKey;

        $this->session = array(
            'token'       => '',
            'expiry'      => '',
            'username'    => '',
            'ip'          => '',
            'hwid'        => '',
            'level'       => 0,
            'subscriptionId' => null,
            'subscriptionName' => null,
            'features'    => array(),
            'limits'      => array(),
            'isValid'     => false,
            'updateLink'  => '',
        );
        $this->appData = array(
            'name'     => '',
            'version'  => '',
            'status'   => '',
            'hwidLock' => false,
        );

        $this->hwid = self::computeHwid();
        $this->hash = self::computeHash();
    }

    // ---------------------------------------------------------------------- //
    // Authentication
    // ---------------------------------------------------------------------- //

    /**
     * Authenticate using the configured license key.
     *
     * @return bool True on success (session and app data are populated).
     */
    public function login()
    {
        if ($this->licenseKey === '') {
            $this->lastError = 'authenticity: license key is empty';
            return false;
        }
        $body = array(
            'ownerId'    => $this->ownerId,
            'appId'      => $this->appId,
            'licenseKey' => $this->licenseKey,
            'hwid'       => $this->hwid,
            'version'    => $this->version,
            'hash'       => $this->hash,
        );
        $resp = $this->request('/auth/login', $body, false);
        if ($resp === null) {
            return false;
        }
        return $this->applyLoginResponse($resp);
    }

    /**
     * Authenticate using a username/password pair.
     *
     * @param string $username Username.
     * @param string $password Password.
     * @return bool True on success.
     */
    public function loginWithCredentials($username, $password)
    {
        if ($username === '' || $password === '') {
            $this->lastError = 'authenticity: username and password are required';
            return false;
        }
        $body = array(
            'ownerId'  => $this->ownerId,
            'appId'    => $this->appId,
            'username' => $username,
            'password' => $password,
            'hwid'     => $this->hwid,
            'version'  => $this->version,
            'hash'     => $this->hash,
        );
        $resp = $this->request('/auth/login-user', $body, false);
        if ($resp === null) {
            return false;
        }
        return $this->applyLoginResponse($resp);
    }

    /** Check for a server update before login. Returns null on failure. */
    public function checkForUpdate()
    {
        $resp = $this->request('/app/update', array(
            'ownerId' => $this->ownerId,
            'appId'   => $this->appId,
            'version' => $this->version,
        ), false);
        if ($resp === null || !$this->isSuccess($resp)) {
            if ($resp !== null) {
                $this->lastError = $this->getString($resp, 'message', 'update check failed');
            }
            return null;
        }
        return array(
            'updateRequired' => $this->isTruthy($this->getValue($resp, 'updateRequired')),
            'clientVersion'  => $this->getString($resp, 'clientVersion', $this->version),
            'currentVersion' => $this->getString($resp, 'currentVersion', ''),
            'updateLink'     => $this->getString($resp, 'updateLink', ''),
            'appName'        => $this->getString($resp, 'appName', ''),
            'appStatus'      => $this->getString($resp, 'appStatus', ''),
        );
    }


    /**
     * Register a new user account on the server.
     *
     * @param string $username   Username for the new account.
     * @param string $password   Password for the new account.
     * @param string $licenseKey License key to bind.
     * @return bool True when the server responds with success == true.
     */
    public function register($username, $password, $licenseKey)
    {
        if ($username === '' || $password === '') {
            $this->lastError = 'authenticity: username and password are required';
            return false;
        }
        $body = array(
            'ownerId'    => $this->ownerId,
            'appId'      => $this->appId,
            'username'   => $username,
            'password'   => $password,
            'licenseKey' => $licenseKey,
            'hwid'       => $this->hwid,
            'version'    => $this->version,
            'hash'       => $this->hash,
        );
        $resp = $this->request('/auth/register', $body, false);
        if ($resp === null) {
            return false;
        }
        $ok = $this->isSuccess($resp);
        if (!$ok) {
            $this->lastError = $this->getString($resp, 'message', 'registration failed');
        }
        return $ok;
    }

    /**
     * Heartbeat / session validation against /auth/check.
     *
     * Returns true while the session is valid. On failure it reads the
     * server's 'expired' and 'reason' fields into lastError and invalidates
     * the local session.
     *
     * @return bool True when the session is still valid.
     */
    public function checkSession()
    {
        if (!$this->session['isValid'] || $this->session['token'] === '') {
            $this->session['isValid'] = false;
            $this->lastError = 'authenticity: not logged in';
            return false;
        }
        $body = array(
            'token' => $this->session['token'],
            'appId' => $this->appId,
            'hwid' => $this->hwid,
        );
        $resp = $this->request('/auth/check', $body, true);
        if ($resp === null) {
            return false;
        }
        if ($this->isSuccess($resp)) {
            $this->session['isValid'] = true;
            $this->applySubscriptionFields($resp);
            $this->lastError = '';
            return true;
        }

        $this->session['isValid'] = false;
        $expired = $this->isTruthy($this->getValue($resp, 'expired'));
        $reason  = $this->getString($resp, 'reason', $this->getString($resp, 'message', ''));
        if ($expired && $reason !== '') {
            $this->lastError = 'authenticity: session expired: ' . $reason;
        } elseif ($expired) {
            $this->lastError = 'authenticity: session expired';
        } elseif ($reason !== '') {
            $this->lastError = 'authenticity: check failed: ' . $reason;
        } else {
            $this->lastError = 'authenticity: session check failed';
        }
        return false;
    }

    /** Ask the server whether the current subscription grants a feature. */
    public function hasFeature($feature)
    {
        if (!is_string($feature) || trim($feature) === '' || !$this->session['isValid'] || $this->session['token'] === '') return false;
        $resp = $this->request('/auth/check', array(
            'token' => $this->session['token'], 'appId' => $this->appId,
            'hwid' => $this->hwid, 'feature' => $feature,
        ), true);
        if ($resp === null || !$this->isSuccess($resp)) return false;
        $this->applySubscriptionFields($resp);
        return true;
    }

    private function applySubscriptionFields($resp)
    {
        if (array_key_exists('subscriptionId', $resp)) $this->session['subscriptionId'] = $resp['subscriptionId'];
        if (array_key_exists('subscriptionName', $resp)) $this->session['subscriptionName'] = $resp['subscriptionName'];
        if (array_key_exists('level', $resp)) $this->session['level'] = $this->getInt($resp, 'level', $this->session['level']);
        if (isset($resp['features']) && is_array($resp['features']))
            $this->session['features'] = array_values(array_filter($resp['features'], 'is_string'));
        if (isset($resp['limits']) && is_array($resp['limits'])) {
            $limits = array();
            foreach ($resp['limits'] as $key => $value)
                if (is_string($key) && is_int($value) && $value >= 0) $limits[$key] = $value;
            $this->session['limits'] = $limits;
        }
    }


    /**
     * Check whether the current hardware is blacklisted.
     *
     * The server returns success == true when the HWID is NOT blacklisted, so
     * the result is inverted here: this method returns true when the machine
     * IS blacklisted (mirroring the Go/Python/Java SDKs).
     *
     * @return bool True when the machine is blacklisted.
     */
    public function checkBlacklist()
    {
        $body = array(
            'ownerId' => $this->ownerId,
            'appId'   => $this->appId,
            'hwid'    => $this->hwid,
        );
        $resp = $this->request('/auth/check-blacklist', $body, false);
        if ($resp === null) {
            return false;
        }
        if ($this->isSuccess($resp)) {
            // success == true means NOT blacklisted.
            $this->lastError = '';
            return false;
        }
        $this->lastError = $this->getString($resp, 'message', 'hardware is blacklisted');
        return true;
    }

    /**
     * Self-ban: report an abuse reason and invalidate the local session.
     *
     * @param string $reason Why the ban is being requested.
     * @return bool True on success.
     */
    public function ban($reason)
    {
        if (!$this->session['isValid'] || $this->session['token'] === '') {
            $this->lastError = 'authenticity: not logged in';
            return false;
        }
        $body = array(
            'token'  => $this->session['token'],
            'appId'  => $this->appId,
            'reason' => $reason,
        );
        $resp = $this->request('/auth/ban', $body, true);
        if ($resp === null) {
            return false;
        }
        $ok = $this->isSuccess($resp);
        // The session is invalidated regardless of outcome.
        $this->session['isValid'] = false;
        if (!$ok) {
            $this->lastError = $this->getString($resp, 'message', 'ban request failed');
            return false;
        }
        $this->lastError = '';
        return true;
    }


    // ---------------------------------------------------------------------- //
    // Features
    // ---------------------------------------------------------------------- //

    /**
     * Fetch the value of a server-side variable.
     *
     * @param string $name Variable name.
     * @return string The value, or '' on failure.
     */
    public function getVariable($name)
    {
        if ($name === '') {
            $this->lastError = 'authenticity: variable name is required';
            return '';
        }
        if (!$this->sessionValid()) {
            return '';
        }
        $body = array(
            'token' => $this->session['token'],
            'appId' => $this->appId,
            'name'  => $name,
        );
        $resp = $this->request('/vars/get', $body, true);
        if ($resp === null) {
            return '';
        }
        if (!$this->isSuccess($resp)) {
            $this->lastError = $this->getString($resp, 'message', 'failed to fetch variable ' . $name);
            return '';
        }
        $this->lastError = '';
        return $this->getString($resp, 'value', '');
    }

    /**
     * Download a file: resolve the download URL via /files/download, then GET
     * the URL to retrieve the raw bytes.
     *
     * @param string $fileId File identifier.
     * @return string The raw file bytes, or '' on failure.
     */
    public function downloadFile($fileId)
    {
        $url = $this->resolveDownloadUrl($fileId);
        if ($url === null) {
            return '';
        }
        $data = $this->httpGet($url);
        if ($data === null) {
            return '';
        }
        $this->lastError = '';
        return $data;
    }

    /**
     * Resolve a file's download URL and open it in the default browser.
     *
     * @param string $fileId File identifier.
     * @return bool True when the browser was successfully invoked.
     */
    public function downloadFileDirect($fileId)
    {
        $url = $this->resolveDownloadUrl($fileId);
        if ($url === null) {
            return false;
        }
        if (!$this->openUrl($url)) {
            $this->lastError = 'authenticity: failed to open url: ' . $url;
            return false;
        }
        $this->lastError = '';
        return true;
    }

    /**
     * Trigger a named webhook with arbitrary data.
     *
     * @param string       $name Webhook name.
     * @param array|string $data Arbitrary payload (array or string).
     * @return bool True when the server acknowledges success.
     */
    public function triggerWebhook($name, $data)
    {
        if ($name === '') {
            $this->lastError = 'authenticity: webhook name is required';
            return false;
        }
        if (!$this->sessionValid()) {
            return false;
        }
        if (!is_string($data)) {
            $data = json_encode($data === null ? array() : $data);
            if ($data === false) {
                $this->lastError = 'authenticity: failed to encode webhook data';
                return false;
            }
        }
        $body = array(
            'token'       => $this->session['token'],
            'appId'       => $this->appId,
            'webhookName' => $name,
            'data'        => $data,
        );
        $resp = $this->request('/webhooks/trigger', $body, true);
        if ($resp === null) {
            return false;
        }
        $ok = $this->isSuccess($resp);
        if (!$ok) {
            $this->lastError = $this->getString($resp, 'message', 'webhook trigger failed');
            return false;
        }
        $this->lastError = '';
        return true;
    }

    /**
     * Send a log entry to the server. It is a no-op unless the session is
     * valid. The type parameter defaults to 'info' when empty.
     *
     * @param mixed  $data Log payload.
     * @param string $type Log type.
     * @return void
     */
    public function log($data, $type)
    {
        if (!$this->sessionValid()) {
            return;
        }
        if (!is_string($data)) {
            $data = json_encode($data === null ? array() : $data);
            if ($data === false) {
                $this->lastError = 'authenticity: failed to encode log data';
                return;
            }
        }
        if ($type === '') {
            $type = 'info';
        }
        $body = array(
            'token' => $this->session['token'],
            'appId' => $this->appId,
            'data'  => $data,
            'type'  => $type,
        );
        $resp = $this->request('/logs/add', $body, true);
        // No-op regardless of outcome; errors are surfaced via getLastError().
        if ($resp !== null) {
            $this->lastError = '';
        }
    }


    // ---------------------------------------------------------------------- //
    // Chat
    // ---------------------------------------------------------------------- //

    /**
     * Fetch the list of available chat channels.
     *
     * @return array List of channel arrays: [id, name, cooldownUnit, cooldownTime].
     */
    public function getChannels()
    {
        if (!$this->sessionValid()) {
            return array();
        }
        $body = array(
            'token' => $this->session['token'],
            'appId' => $this->appId,
        );
        $resp = $this->request('/chat/channels', $body, true);
        if ($resp === null) {
            return array();
        }
        $arr = $this->getArray($resp, 'channels');
        if ($arr === null) {
            $this->lastError = $this->getString($resp, 'message', 'failed to fetch channels');
            return array();
        }
        $out = array();
        foreach ($arr as $item) {
            if (!is_array($item)) {
                continue;
            }
            $out[] = array(
                'id'           => $this->getString($item, 'id', ''),
                'name'         => $this->getString($item, 'name', ''),
                'cooldownUnit' => $this->getString($item, 'cooldownUnit', $this->getString($item, 'cooldown_unit', '')),
                'cooldownTime' => $this->getInt($item, 'cooldownTime', $this->getInt($item, 'cooldown_time', 0)),
            );
        }
        $this->lastError = '';
        return $out;
    }

    /**
     * Fetch messages for a channel. Use channelId 'all' to fetch messages from
     * every channel.
     *
     * @param string $channelId Channel identifier, or 'all'.
     * @return array List of message arrays with channelId, senderId and avatarId.
     */
    public function getMessages($channelId)
    {
        if (!$this->sessionValid()) {
            return array();
        }
        if ($channelId === '') {
            $channelId = 'all';
        }
        $body = array(
            'token'     => $this->session['token'],
            'appId'     => $this->appId,
            'channelId' => $channelId,
        );
        $resp = $this->request('/chat/messages', $body, true);
        if ($resp === null) {
            return array();
        }
        $arr = $this->getArray($resp, 'messages');
        if ($arr === null) {
            $this->lastError = $this->getString($resp, 'message', 'failed to fetch messages');
            return array();
        }
        $out = array();
        foreach ($arr as $item) {
            if (!is_array($item)) {
                continue;
            }
            $out[] = array(
                'id'       => $this->getString($item, 'id', ''),
                'channelId' => $this->getString($item, 'channelId', ''),
                'senderId' => $this->getString($item, 'senderId', ''),
                'sender'   => $this->getString($item, 'sender', $this->getString($item, 'author', '')),
                'avatarId' => $this->getString($item, 'avatarId', ''),
                'content'  => $this->getString($item, 'content', $this->getString($item, 'text', '')),
                'timeSent' => $this->getString(
                    $item,
                    'timeSent',
                    $this->getString($item, 'timestamp', $this->getString($item, 'time_sent', ''))
                ),
            );
        }
        $this->lastError = '';
        return $out;
    }

    /**
     * Post a new message to a channel.
     *
     * @param string $channelId Channel identifier.
     * @param string $content   Message body.
     * @return bool True on success.
     */
    public function sendMessage($channelId, $content)
    {
        if ($channelId === '' || $content === '') {
            $this->lastError = 'authenticity: channelId and content are required';
            return false;
        }
        if (!$this->sessionValid()) {
            return false;
        }
        $body = array(
            'token'     => $this->session['token'],
            'appId'     => $this->appId,
            'channelId' => $channelId,
            'content'   => $content,
        );
        $resp = $this->request('/chat/messages', $body, true, 'PUT');
        if ($resp === null) {
            return false;
        }
        $ok = $this->isSuccess($resp);
        if (!$ok) {
            $this->lastError = $this->getString($resp, 'message', 'failed to send message');
            return false;
        }
        $this->lastError = '';
        return true;
    }

    /** Return the current user's chat identity, or null on failure. */
    public function getChatProfile()
    {
        if (!$this->sessionValid()) return null;
        $resp = $this->request('/chat/profile', array(
            'token' => $this->session['token'], 'appId' => $this->appId,
        ), true);
        if ($resp === null) return null;
        if (!$this->isSuccess($resp)) {
            $this->lastError = $this->getString($resp, 'message', 'failed to fetch chat profile');
            return null;
        }
        $this->lastError = '';
        return array('id' => $this->getString($resp, 'profileId', ''),
            'nickname' => $this->getString($resp, 'nickname', ''),
            'avatarId' => $this->getString($resp, 'avatarId', ''));
    }

    /** Update the current user's chat nickname and application avatar ID. */
    public function updateChatProfile($nickname, $avatarId)
    {
        if (!$this->sessionValid()) return null;
        $resp = $this->request('/chat/profile', array(
            'token' => $this->session['token'], 'appId' => $this->appId,
            'nickname' => $nickname, 'avatarId' => $avatarId,
        ), true, 'PUT');
        if ($resp === null) return null;
        if (!$this->isSuccess($resp)) {
            $this->lastError = $this->getString($resp, 'message', 'failed to update chat profile');
            return null;
        }
        $this->lastError = '';
        return array('id' => $this->getString($resp, 'profileId', ''),
            'nickname' => $this->getString($resp, 'nickname', ''),
            'avatarId' => $this->getString($resp, 'avatarId', ''));
    }


    // ---------------------------------------------------------------------- //
    // Getters & helpers
    // ---------------------------------------------------------------------- //

    /**
     * Set / update the client's license key.
     *
     * @param string $key License key.
     * @return void
     */
    public function setLicenseKey($key)
    {
        $this->licenseKey = (string)$key;
    }

    /**
     * Return the current session state.
     *
     * @return array With keys: token, expiry, username, ip, hwid, level (int),
     *               isValid (bool), updateLink.
     */
    public function getSession()
    {
        return $this->session;
    }

    /**
     * Return the current application metadata.
     *
     * @return array With keys: name, version, status, hwidLock (bool).
     */
    public function getAppData()
    {
        return $this->appData;
    }

    /**
     * Return the most recent error message, or '' if there is none.
     *
     * @return string
     */
    public function getLastError()
    {
        return $this->lastError;
    }

    /**
     * Return the update link from the session. Login responses do not include
     * an update link, so this typically returns ''; the field is retained for
     * parity with the other SDKs.
     *
     * @return string
     */
    public function getUpdateLink()
    {
        return $this->session['updateLink'];
    }

    /**
     * Return the generated hardware ID of this machine.
     *
     * @return string
     */
    public function getHwid()
    {
        return $this->hwid;
    }

    /**
     * Return the secondary machine hash (MD5 of the running script).
     *
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * Compute a human-readable remaining-time string from the session expiry,
     * in the format used by the other SDKs:
     *
     *     "X Years : X Months : X Days : X Hours : X Mins"
     *
     * The server expiry string is parsed leniently; if it cannot be interpreted
     * an all-zero breakdown is returned.
     *
     * @return string
     */
    public function getRemainingTime()
    {
        list($years, $months, $days, $hours, $mins) = $this->remainingBreakdown();
        return sprintf(
            '%d Years : %d Months : %d Days : %d Hours : %d Mins',
            $years,
            $months,
            $days,
            $hours,
            $mins
        );
    }


    // ---------------------------------------------------------------------- //
    // Auto-login credentials (login.json)
    // ---------------------------------------------------------------------- //

    /**
     * Persist the auto-login credentials to login.json next to the running
     * script.
     *
     * Validation follows the shared SDK contract:
     *   - LoginType 1 (license) is valid when the license key is non-empty.
     *   - LoginType 2 (username/password) is valid when both are non-empty.
     *
     * @param int    $loginType   1 = license, 2 = username/password.
     * @param string $licenseKey  License key (loginType 1).
     * @param string $username    Username (loginType 2).
     * @param string $password    Password (loginType 2).
     * @return bool True on success.
     */
    public function saveCredentials($loginType, $licenseKey, $username, $password)
    {
        $creds = array(
            'loginType'  => (int)$loginType,
            'licenseKey' => $licenseKey,
            'username'   => $username,
            'password'   => $password,
            'isValid'    => self::credentialsValid($loginType, $licenseKey, $username, $password),
        );

        $path = self::credentialsPath();
        if ($path === '') {
            $this->lastError = 'authenticity: cannot locate working directory';
            return false;
        }

        $data = json_encode($creds, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $tmp = $path . '.tmp';
        if (@file_put_contents($tmp, $data, LOCK_EX) === false) {
            $this->lastError = 'authenticity: failed to write credentials';
            return false;
        }
        // Best-effort: restrict permissions on POSIX systems.
        @chmod($tmp, 0600);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            $this->lastError = 'authenticity: failed to write credentials';
            return false;
        }
        $this->lastError = '';
        return true;
    }

    /**
     * Read the saved auto-login credentials from login.json.
     *
     * @return array With keys: loginType, licenseKey, username, password,
     *               isValid (bool).
     */
    public function loadCredentials()
    {
        $path = self::credentialsPath();
        if ($path === '') {
            $this->lastError = 'authenticity: cannot locate working directory';
            return self::emptyCredentials();
        }

        if (!is_file($path)) {
            $this->lastError = '';
            return self::emptyCredentials();
        }
        $data = @file_get_contents($path);
        if ($data === false) {
            $this->lastError = 'authenticity: failed to read credentials';
            return self::emptyCredentials();
        }
        $creds = @json_decode($data, true);
        if (!is_array($creds)) {
            $this->lastError = 'authenticity: failed to parse credentials';
            return self::emptyCredentials();
        }

        $creds = array_merge(self::emptyCredentials(), $creds);
        $creds['loginType'] = (int)$creds['loginType'];
        $creds['isValid'] = self::credentialsValid(
            $creds['loginType'],
            $creds['licenseKey'],
            $creds['username'],
            $creds['password']
        );
        $this->lastError = '';
        return $creds;
    }

    /**
     * Remove the saved auto-login file. Returns true when the file was removed
     * (or did not already exist).
     *
     * @return bool
     */
    public function deleteCredentials()
    {
        $path = self::credentialsPath();
        if ($path === '') {
            $this->lastError = 'authenticity: cannot locate working directory';
            return false;
        }
        if (!file_exists($path)) {
            $this->lastError = '';
            return true;
        }
        if (!@unlink($path)) {
            $this->lastError = 'authenticity: failed to delete credentials';
            return false;
        }
        $this->lastError = '';
        return true;
    }

    /**
     * Convenience static wrapper around saveCredentials (matches the Python
     * SDK's static usage). Returns true on success.
     *
     * @param int    $loginType   1 = license, 2 = username/password.
     * @param string $licenseKey  License key (loginType 1).
     * @param string $username    Username (loginType 2).
     * @param string $password    Password (loginType 2).
     * @return bool
     */
    public static function saveCredentialsStatic($loginType, $licenseKey = '', $username = '', $password = '')
    {
        $client = new self('', '', '', '');
        return $client->saveCredentials($loginType, $licenseKey, $username, $password);
    }

    /**
     * Convenience static wrapper around loadCredentials.
     *
     * @return array Saved credentials array.
     */
    public static function loadCredentialsStatic()
    {
        $client = new self('', '', '', '');
        return $client->loadCredentials();
    }

    /**
     * Convenience static wrapper around deleteCredentials.
     *
     * @return bool
     */
    public static function deleteCredentialsStatic()
    {
        $client = new self('', '', '', '');
        return $client->deleteCredentials();
    }


    // ---------------------------------------------------------------------- //
    // HTTP internals
    // ---------------------------------------------------------------------- //

    /**
     * Perform an HTTP JSON request with a JSON body and return the decoded
     * response as an associative array (or null on a hard network failure).
     *
     * Authenticated endpoints additionally send the token as
     * "Authorization: Bearer <token>" (and the token is included in the body
     * by the caller).
     *
     * @param string $endpoint   Relative endpoint path (leading "/").
     * @param array  $body       Associative array to encode as JSON.
     * @param bool   $authorized Whether to attach the bearer token header.
     * @param string $method     HTTP method (POST by default; PUT for comments).
     * @return array|null
     */
    private function request($endpoint, $body, $authorized, $method = 'POST')
    {
        if ($this->apiUrl === '') {
            $this->lastError = 'authenticity: APIURL is not set';
            return null;
        }

        $payload = @json_encode($body);
        if ($payload === false) {
            $this->lastError = 'authenticity: failed to encode request body';
            return null;
        }

        $headers = array(
            'Content-Type: application/json',
            'User-Agent: ' . self::USER_AGENT,
        );
        if ($authorized && $this->session['token'] !== '') {
            $headers[] = 'Authorization: Bearer ' . $this->session['token'];
        }

        $ch = curl_init($this->apiUrl . $endpoint);
        if ($ch === false) {
            $this->lastError = 'authenticity: failed to initialize cURL';
            return null;
        }

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, self::REQUEST_TIMEOUT);
        curl_setopt($ch, CURLOPT_TIMEOUT, self::REQUEST_TIMEOUT);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        $result = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno  = curl_errno($ch);
        $error  = curl_error($ch);
        curl_close($ch);

        if ($result === false || $errno !== 0) {
            $msg = $error !== '' ? $error : 'unknown cURL error';
            $this->lastError = 'authenticity: network error: ' . $msg;
            return null;
        }

        $data = @json_decode($result, true);
        if (!is_array($data)) {
            $data = array();
        }

        // Surface non-2xx status as an error but keep the parsed body so
        // callers can extract business fields (e.g. expiry/reason).
        if ($status < 200 || $status >= 300) {
            $msg = $this->getString($data, 'message', '');
            if ($msg === '') {
                $msg = 'HTTP status ' . $status;
            }
            $this->lastError = $msg;
            return $data;
        }

        $this->lastError = '';
        return $data;
    }

    /**
     * Perform a plain HTTP GET request and return the raw body bytes, or null
     * on failure. Used for file downloads.
     *
     * @param string $rawURL Absolute URL to GET.
     * @return string|null
     */
    private function httpGet($rawURL)
    {
        $headers = array('User-Agent: ' . self::USER_AGENT);

        $ch = curl_init($rawURL);
        if ($ch === false) {
            $this->lastError = 'authenticity: failed to initialize cURL';
            return null;
        }

        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, self::REQUEST_TIMEOUT);
        curl_setopt($ch, CURLOPT_TIMEOUT, self::REQUEST_TIMEOUT);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        $result = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno  = curl_errno($ch);
        $error  = curl_error($ch);
        curl_close($ch);

        if ($result === false || $errno !== 0) {
            $msg = $error !== '' ? $error : 'unknown cURL error';
            $this->lastError = 'authenticity: download network error: ' . $msg;
            return null;
        }
        if ($status < 200 || $status >= 300) {
            $snippet = trim((string)$result);
            $msg = 'download returned HTTP ' . $status;
            if ($snippet !== '' && strlen($snippet) < 256) {
                $msg .= ': ' . $snippet;
            }
            $this->lastError = $msg;
            return null;
        }
        $this->lastError = '';
        return $result;
    }

    /**
     * Resolve a file's download URL via /files/download.
     *
     * @param string $fileId File identifier.
     * @return string|null The resolved URL, or null on failure.
     */
    private function resolveDownloadUrl($fileId)
    {
        if ($fileId === '') {
            $this->lastError = 'authenticity: fileId is required';
            return null;
        }
        if (!$this->sessionValid()) {
            return null;
        }
        $body = array(
            'token'  => $this->session['token'],
            'appId'  => $this->appId,
            'fileId' => $fileId,
        );
        $resp = $this->request('/files/download', $body, true);
        if ($resp === null) {
            return null;
        }
        if (!$this->isSuccess($resp)) {
            $this->lastError = $this->getString($resp, 'message', 'failed to fetch download url');
            return null;
        }
        $url = $this->getString($resp, 'url', $this->getString($resp, 'downloadUrl', ''));
        if ($url === '') {
            $this->lastError = 'authenticity: file download url is empty';
            return null;
        }
        return $url;
    }


    // ---------------------------------------------------------------------- //
    // Internal helpers
    // ---------------------------------------------------------------------- //

    /**
     * Apply a successful (or failed) login response to the client's Session and
     * AppData. Returns true on success.
     *
     * @param array $resp Decoded JSON response.
     * @return bool
     */
    private function applyLoginResponse($resp)
    {
        $ok = $this->isSuccess($resp);
        if (!$ok) {
            $this->session['updateLink'] = $this->getString($resp, 'updateLink', '');
            $this->lastError = $this->getString($resp, 'message', 'login failed');
            $this->session['isValid'] = false;
            return false;
        }

        $token = $this->getString($resp, 'token', '');
        if ($token === '') {
            $this->session['isValid'] = false;
            $this->session['updateLink'] = $this->getString($resp, 'updateLink', '');
            $this->lastError = 'authenticity: login response did not include a session token';
            return false;
        }

        $this->session = array(
            'token'      => $token,
            'expiry'     => $this->getString($resp, 'expiry', ''),
            'username'   => $this->getString($resp, 'username', ''),
            'ip'         => $this->getString($resp, 'ip', ''),
            'hwid'       => $this->getString($resp, 'hwid', $this->hwid),
            'level'      => $this->getInt($resp, 'level', 0),
            'subscriptionId' => isset($resp['subscriptionId']) ? $resp['subscriptionId'] : null,
            'subscriptionName' => isset($resp['subscriptionName']) ? $resp['subscriptionName'] : null,
            'features' => isset($resp['features']) && is_array($resp['features']) ? array_values(array_filter($resp['features'], 'is_string')) : array(),
            'limits' => isset($resp['limits']) && is_array($resp['limits']) ? $resp['limits'] : array(),
            'isValid'    => true,
            'updateLink' => $this->getString($resp, 'updateLink', ''),
        );
        $this->applySubscriptionFields($resp);
        $this->appData = array(
            'name'     => $this->getString($resp, 'appName', ''),
            'version'  => $this->getString($resp, 'appVersion', ''),
            'status'   => $this->getString($resp, 'appStatus', ''),
            'hwidLock' => $this->isTruthy($this->getValue($resp, 'hwidLock')),
        );
        $this->lastError = '';
        return true;
    }

    /**
     * Report whether the session is valid (a token exists and it is marked
     * valid). Recording an error on failure.
     *
     * @return bool
     */
    private function sessionValid()
    {
        if ($this->session['token'] === '' || !$this->session['isValid']) {
            $this->lastError = 'authenticity: not logged in or session invalid';
            return false;
        }
        return true;
    }

    /**
     * Decompose the session expiry into calendar parts. Best-effort parse of
     * the server-provided expiry timestamp.
     *
     * @return array [years, months, days, hours, mins]
     */
    private function remainingBreakdown()
    {
        $exp = trim($this->session['expiry']);
        if ($exp === '') {
            return array(0, 0, 0, 0, 0);
        }

        // Lifetime licenses are returned by the server as the literal "Never".
        if (strcasecmp($exp, 'Never') === 0) {
            $exp = '2099-12-31T00:00:00Z';
        }

        $timestamp = $this->parseTime($exp);
        if ($timestamp === null) {
            return array(0, 0, 0, 0, 0);
        }

        $now = time();
        if ($timestamp <= $now) {
            return array(0, 0, 0, 0, 0);
        }

        $diff = $timestamp - $now;
        $years = intdiv($diff, 365 * 24 * 3600);
        $diff -= $years * 365 * 24 * 3600;
        $months = intdiv($diff, 30 * 24 * 3600);
        $diff -= $months * 30 * 24 * 3600;
        $days = intdiv($diff, 24 * 3600);
        $diff -= $days * 24 * 3600;
        $hours = intdiv($diff, 3600);
        $diff -= $hours * 3600;
        $mins = intdiv($diff, 60);
        return array($years, $months, $days, $hours, $mins);
    }

    /**
     * Leniently parse a date/time string into a Unix timestamp, or null when it
     * cannot be interpreted. Supports ISO-8601 (with 'Z' or offset), common
     * separators, and raw millisecond epoch values.
     *
     * @param string $value Timestamp string.
     * @return int|null
     */
    private function parseTime($value)
    {
        $text = trim($value);

        // Raw numeric epoch (seconds or milliseconds).
        if (preg_match('/^\d+$/', $text)) {
            $num = (int)$text;
            if ($num > 100000000000) {
                // Looks like milliseconds.
                return (int)floor($num / 1000);
            }
            return $num;
        }

        // Normalize ISO-8601 "Z" suffix to an explicit +00:00 offset so that
        // strtotime can parse it reliably.
        $normalized = $text;
        if (substr($normalized, -1) === 'Z') {
            $normalized = substr($normalized, 0, -1) . '+00:00';
        }
        $ts = strtotime($normalized);
        if ($ts !== false && $ts > 0) {
            return $ts;
        }

        // Fallback: strip fractional seconds and timezone suffix.
        $cleaned = $text;
        if (strpos($cleaned, '.') !== false) {
            $cleaned = substr($cleaned, 0, strpos($cleaned, '.'));
        }
        $cleaned = str_replace(array('Z', '+00:00', 'T'), array('', '', ' '), $cleaned);
        $ts = strtotime($cleaned);
        if ($ts !== false && $ts > 0) {
            return $ts;
        }

        return null;
    }


    // ---------------------------------------------------------------------- //
    // Response accessors (tolerant field reading)
    // ---------------------------------------------------------------------- //

    /**
     * Return whether a decoded response indicates success.
     *
     * The server returns success as a string ("true"/"false") in many
     * responses and as a real boolean in others, so both forms are tolerated:
     * "true" (case-insensitive), true, and 1 all count as success; anything
     * else (including "false", missing, or null) counts as failure.
     *
     * @param array $resp Decoded JSON response.
     * @return bool
     */
    private function isSuccess($resp)
    {
        return $this->isTruthy($this->getValue($resp, 'success'));
    }

    /**
     * Coerce an arbitrary server value into a boolean following the tolerant
     * success rules described in isSuccess().
     *
     * @param mixed $value Raw decoded value.
     * @return bool
     */
    private function isTruthy($value)
    {
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return $value == 1;
        }
        if (is_string($value)) {
            $v = strtolower(trim($value));
            if ($v === 'true' || $v === '1') {
                return true;
            }
            if ($v === 'false' || $v === '0' || $v === '') {
                return false;
            }
            // Any other non-empty string is treated as truthy for tolerance.
            return true;
        }
        return false;
    }

    /**
     * Fetch a raw value from a decoded response, or null when missing.
     *
     * @param array  $resp Response array.
     * @param string $key  Field key.
     * @return mixed|null
     */
    private function getValue($resp, $key)
    {
        return isset($resp[$key]) ? $resp[$key] : null;
    }

    /**
     * Fetch a string value from a decoded response, or a default when missing
     * or not a string.
     *
     * @param array  $resp Response array.
     * @param string $key  Field key.
     * @param string $def  Default value.
     * @return string
     */
    private function getString($resp, $key, $def)
    {
        if (is_array($resp) && isset($resp[$key])) {
            if (is_string($resp[$key])) {
                return $resp[$key];
            }
            if (is_scalar($resp[$key])) {
                return (string)$resp[$key];
            }
        }
        return $def;
    }

    /**
     * Fetch an integer value from a decoded response, or a default when
     * missing or not coercible to an int.
     *
     * @param array  $resp Response array.
     * @param string $key  Field key.
     * @param int    $def  Default value.
     * @return int
     */
    private function getInt($resp, $key, $def)
    {
        if (is_array($resp) && isset($resp[$key]) && is_numeric($resp[$key])) {
            return (int)$resp[$key];
        }
        return $def;
    }

    /**
     * Fetch an array value from a decoded response, or null when missing or
     * not an array.
     *
     * @param array  $resp Response array.
     * @param string $key  Field key.
     * @return array|null
     */
    private function getArray($resp, $key)
    {
        if (is_array($resp) && isset($resp[$key]) && is_array($resp[$key])) {
            return $resp[$key];
        }
        return null;
    }

    /**
     * Open a URL in the platform's default browser. Best-effort; returns
     * whether a handler was successfully launched.
     *
     * @param string $url URL to open.
     * @return bool
     */
    private function openUrl($url)
    {
        $os = strtolower(PHP_OS_FAMILY);
        $cmd = null;
        if ($os === 'windows') {
            $cmd = 'start "" ' . escapeshellarg($url);
            $pipes = array();
            $proc = @proc_open($cmd, array(), $pipes);
            if (is_resource($proc)) {
                proc_close($proc);
                return true;
            }
            return false;
        }
        if ($os === 'darwin') {
            $cmd = 'open ' . escapeshellarg($url);
        } else {
            $cmd = 'xdg-open ' . escapeshellarg($url);
        }
        @exec($cmd . ' > /dev/null 2>&1 &');
        return true;
    }


    // ---------------------------------------------------------------------- //
    // Credential helpers (static)
    // ---------------------------------------------------------------------- //

    /**
     * Return a default (empty) saved-credentials array.
     *
     * @return array
     */
    private static function emptyCredentials()
    {
        return array(
            'loginType'  => 0,
            'licenseKey' => '',
            'username'   => '',
            'password'   => '',
            'isValid'    => false,
        );
    }

    /**
     * Resolve the absolute path to login.json, which is stored next to the
     * running script (the entry point that includes this SDK).
     *
     * @return string Absolute path, or '' when it cannot be determined.
     */
    public static function credentialsPath()
    {
        $dir = self::scriptDirectory();
        if ($dir === '') {
            return '';
        }
        return $dir . DIRECTORY_SEPARATOR . self::LOGIN_JSON_FILE;
    }

    /**
     * Determine the directory of the running script (the entry point that
     * includes this SDK, mirroring "next to the executable" in the other
     * SDKs). Best-effort: falls back to the current working directory.
     *
     * @return string
     */
    private static function scriptDirectory()
    {
        if (isset($_SERVER['SCRIPT_FILENAME']) && $_SERVER['SCRIPT_FILENAME'] !== '') {
            $dir = dirname($_SERVER['SCRIPT_FILENAME']);
            if ($dir !== '' && $dir !== '.') {
                return $dir;
            }
        }
        $cwd = getcwd();
        return $cwd !== false ? $cwd : '';
    }

    /**
     * Implement the shared auto-login validation rules.
     *
     * @param int    $loginType  1 = license, 2 = username/password.
     * @param string $licenseKey License key (loginType 1).
     * @param string $username   Username (loginType 2).
     * @param string $password   Password (loginType 2).
     * @return bool
     */
    private static function credentialsValid($loginType, $licenseKey, $username, $password)
    {
        switch ((int)$loginType) {
            case self::LOGIN_TYPE_LICENSE:
                return $licenseKey !== '';
            case self::LOGIN_TYPE_CREDENTIALS:
                return $username !== '' && $password !== '';
            default:
                return false;
        }
    }


    // ---------------------------------------------------------------------- //
    // HWID & hash generation (static)
    // ---------------------------------------------------------------------- //

    /**
     * Compute a stable, deterministic machine fingerprint (HWID).
     *
     * The raw fingerprint is derived from the hostname and platform machine
     * identifiers (WMI via PowerShell on Windows, machine-id on Linux/macOS).
     * It is hashed with DJB2 (seed 5381) followed by a second DJB2-XOR pass
     * (seed 0xDEADBEEF), then rendered as a lowercase hexadecimal string.
     *
     * Generation is best-effort and returns "UNKNOWN_HWID" on total failure.
     *
     * @return string
     */
    public static function computeHwid()
    {
        try {
            $fp = self::machineFingerprint();
            if ($fp === '') {
                return self::HWID_UNKNOWN;
            }
            $h  = self::djb2($fp);
            $h2 = self::djb2Xor($fp . '|' . $h);
            // Lowercase hex, e.g. sprintf('%x') semantics with zero-padding.
            return self::hex64($h) . self::hex64($h2);
        } catch (\Exception $e) {
            return self::HWID_UNKNOWN;
        }
    }

    /**
     * Compute the secondary machine hash as the MD5 of the running script
     * file (an integrity check), matching the other SDKs (e.g. Python's
     * _hash_executable).
     *
     * @return string MD5 hex digest, or '' on failure.
     */
    public static function computeHash()
    {
        try {
            $path = '';
            if (isset($_SERVER['SCRIPT_FILENAME']) && is_file($_SERVER['SCRIPT_FILENAME'])) {
                $path = $_SERVER['SCRIPT_FILENAME'];
            } else {
                $reflect = new \ReflectionClass(__CLASS__);
                $file = $reflect->getFileName();
                if ($file !== false && is_file($file)) {
                    $path = $file;
                }
            }
            if ($path !== '' && is_file($path)) {
                return md5_file($path);
            }
        } catch (\Exception $e) {
            // fall through
        }
        return '';
    }

    /**
     * A convenience alias for computeHwid(), kept for API-surface parity.
     *
     * @return string
     */
    public static function generateHwid()
    {
        return self::computeHwid();
    }

    /**
     * Compute the classic DJB2 hash (seed 5381). Operates on the raw byte
     * string to stay consistent with the other SDKs.
     *
     * @param string $data Input data.
     * @return int
     */
    private static function djb2($data)
    {
        $h = self::DJB2_SEED;
        // Mask to 64-bit to avoid platform-dependent sign issues.
        $mask = 0xFFFFFFFFFFFFFFFF;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $h = (($h << 5) + $h + ord($data[$i])) & $mask; // h*33 + char
        }
        return $h;
    }

    /**
     * Compute the DJB2-XOR variant seeded with 0xDEADBEEF used for the second
     * HWID pass, mirroring the other SDKs.
     *
     * @param string $data Input data.
     * @return int
     */
    private static function djb2Xor($data)
    {
        $h = self::DJB2_XOR_SEED;
        $mask = 0xFFFFFFFFFFFFFFFF;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $h = (($h << 5) + $h + ord($data[$i])) & $mask;
            $h = ($h ^ ord($data[$i])) & $mask;
        }
        return $h;
    }


    /**
     * Format an integer as a 16-character lowercase hexadecimal string
     * (zero-padded), matching sprintf('%x') semantics with consistent width.
     *
     * @param int $value Hash value.
     * @return string
     */
    private static function hex64($value)
    {
        return str_pad(dechex($value), 16, '0', STR_PAD_LEFT);
    }

    /**
     * Gather stable identifying information about the machine. Best-effort:
     * any failing source is skipped.
     *
     * @return string
     */
    private static function machineFingerprint()
    {
        $parts = array();

        $host = (string)@php_uname('n');
        if ($host === '') {
            $host = (string)@gethostname();
        }
        if ($host !== '') {
            $parts[] = 'host=' . $host;
        }
        $os = strtolower(PHP_OS);
        $parts[] = 'os=' . $os;
        $parts[] = 'arch=' . php_uname('m');

        if ($os === 'win' || strpos($os, 'win') === 0) {
            $info = self::tryWindowsInfo();
        } else {
            $info = self::readFirstLine('/etc/machine-id', 'machine=');
            if ($info === '') {
                $info = self::readFirstLine('/var/lib/dbus/machine-id', 'machine=');
            }
        }
        if ($info !== '') {
            $parts[] = $info;
        }

        if (count($parts) < 3) {
            return '';
        }
        return implode('|', $parts);
    }

    /**
     * Read the first non-empty line of a file, prefixed with the given prefix,
     * or '' on failure.
     *
     * @param string $path   File path.
     * @param string $prefix Prefix to prepend.
     * @return string
     */
    private static function readFirstLine($path, $prefix)
    {
        if (!is_file($path)) {
            return '';
        }
        $data = @file_get_contents($path);
        if ($data === false) {
            return '';
        }
        foreach (explode("\n", $data) as $line) {
            $line = trim($line);
            if ($line !== '') {
                return $prefix . $line;
            }
        }
        return '';
    }

    /**
     * Query WMI via PowerShell for stable machine identifiers on Windows.
     * Best-effort; returns '' on failure (and falls back to the machine GUID).
     *
     * @return string
     */
    private static function tryWindowsInfo()
    {
        $cmds = array(
            '(Get-CimInstance Win32_ComputerSystemProduct).UUID + "|" + (Get-CimInstance Win32_OperatingSystem).SerialNumber',
            '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Cryptography").MachineGuid',
        );
        foreach ($cmds as $cmd) {
            $val = self::runPowerShell($cmd);
            if ($val !== '') {
                return 'hwid=' . $val;
            }
        }
        return '';
    }

    /**
     * Run a PowerShell command and return its trimmed stdout, or '' on failure.
     * Best-effort; never throws.
     *
     * @param string $command PowerShell command text.
     * @return string
     */
    private static function runPowerShell($command)
    {
        $exe = 'powershell';
        if (is_file('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')) {
            $exe = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
        }
        $cmd = sprintf(
            '%s -NoProfile -NonInteractive -Command %s',
            escapeshellarg($exe),
            escapeshellarg($command)
        );
        $output = array();
        $code = 0;
        @exec($cmd . ' 2>NUL', $output, $code);
        $val = trim(implode("\n", $output));
        $val = trim($val, "\r\n \t");
        return $val;
    }
}
