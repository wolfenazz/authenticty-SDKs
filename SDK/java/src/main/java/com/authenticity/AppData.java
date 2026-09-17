package com.authenticity;

/**
 * Application metadata returned by the server alongside the session.
 */
public class AppData {
    private String name = "";
    private String version = "";
    private String status = "";
    private boolean hwidLock = false;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name == null ? "" : name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version == null ? "" : version;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status == null ? "" : status;
    }

    public boolean isHwidLock() {
        return hwidLock;
    }

    public void setHwidLock(boolean hwidLock) {
        this.hwidLock = hwidLock;
    }

    @Override
    public String toString() {
        return "AppData{name='" + name + "', version='" + version
                + "', status='" + status + "', hwidLock=" + hwidLock + "}";
    }
}
