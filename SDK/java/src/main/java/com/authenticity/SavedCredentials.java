package com.authenticity;

/**
 * Saved auto-login credentials (login.json).
 *
 * <p>loginType: 1 = license key, 2 = username/password.</p>
 */
public class SavedCredentials {
    private int loginType ; // 1 = license key, 2 = username/password
    private String licenseKey = "";
    private String username = "";
    private String password = "";
    private boolean isValid = false;

    public int getLoginType() {
        return loginType;
    }

    public void setLoginType(int loginType) {
        this.loginType = loginType;
    }

    public String getLicenseKey() {
        return licenseKey;
    }

    public void setLicenseKey(String licenseKey) {
        this.licenseKey = licenseKey == null ? "" : licenseKey;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username == null ? "" : username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password == null ? "" : password;
    }

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean valid) {
        isValid = valid;
    }

    @Override
    public String toString() {
        return "SavedCredentials{loginType=" + loginType + ", valid=" + isValid + "}";
    }
}
