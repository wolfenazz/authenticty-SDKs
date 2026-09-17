package com.authenticity;

/** Result of a pre-login application version check. */
public class UpdateInfo {
    private final boolean updateRequired;
    private final String clientVersion;
    private final String currentVersion;
    private final String updateLink;
    private final String appName;
    private final String appStatus;

    public UpdateInfo(boolean updateRequired, String clientVersion, String currentVersion,
                      String updateLink, String appName, String appStatus) {
        this.updateRequired = updateRequired;
        this.clientVersion = clientVersion == null ? "" : clientVersion;
        this.currentVersion = currentVersion == null ? "" : currentVersion;
        this.updateLink = updateLink == null ? "" : updateLink;
        this.appName = appName == null ? "" : appName;
        this.appStatus = appStatus == null ? "" : appStatus;
    }

    public boolean isUpdateRequired() { return updateRequired; }
    public String getClientVersion() { return clientVersion; }
    public String getCurrentVersion() { return currentVersion; }
    public String getUpdateLink() { return updateLink; }
    public String getAppName() { return appName; }
    public String getAppStatus() { return appStatus; }
}
