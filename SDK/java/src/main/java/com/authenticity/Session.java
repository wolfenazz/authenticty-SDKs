package com.authenticity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the user's session information returned by a successful login.
 */
public class Session {
    private String token = "";
    private String expiry = "";
    private String username = "";
    private String ip = "";
    private String hwid = "";
    private int level = 0;
    private String subscriptionId;
    private String subscriptionName;
    private List<String> features = new ArrayList<>();
    private Map<String, Integer> limits = new HashMap<>();
    private boolean isValid = false;
    private String updateLink = "";

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token == null ? "" : token;
    }

    public String getExpiry() {
        return expiry;
    }

    public void setExpiry(String expiry) {
        this.expiry = expiry == null ? "" : expiry;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username == null ? "" : username;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip == null ? "" : ip;
    }

    public String getHwid() {
        return hwid;
    }

    public void setHwid(String hwid) {
        this.hwid = hwid == null ? "" : hwid;
    }

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    public String getSubscriptionId() { return subscriptionId; }
    public void setSubscriptionId(String value) { subscriptionId = value; }
    public String getSubscriptionName() { return subscriptionName; }
    public void setSubscriptionName(String value) { subscriptionName = value; }
    public List<String> getFeatures() { return new ArrayList<>(features); }
    public void setFeatures(List<String> value) { features = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public Map<String, Integer> getLimits() { return new HashMap<>(limits); }
    public void setLimits(Map<String, Integer> value) { limits = value == null ? new HashMap<>() : new HashMap<>(value); }

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean valid) {
        isValid = valid;
    }

    public String getUpdateLink() {
        return updateLink;
    }

    public void setUpdateLink(String updateLink) {
        this.updateLink = updateLink == null ? "" : updateLink;
    }

    @Override
    public String toString() {
        return "Session{username='" + username + "', token='" + token
                + "', is_valid=" + isValid + "}";
    }
}
