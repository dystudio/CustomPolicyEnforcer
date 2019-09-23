package com.guavus.keycloak.security;

public class AuditLogs {
    private String Timestamp;
    private String clientIP;
    private String UserID;
    private String Username;
    private String URI;
    private String Action;
    private int Status;

    public String getTimestamp() {
        return Timestamp;
    }

    public void setTimestamp(String timestamp) {
        Timestamp = timestamp;
    }

    public String getClientIP() {
        return clientIP;
    }

    public void setClientIP(String clientIP) {
        this.clientIP = clientIP;
    }

    public String getUserID() {
        return UserID;
    }

    public void setUserID(String userID) {
        this.UserID = userID;
    }

    public String getURI() {
        return URI;
    }

    public String getUsername() {
        return Username;
    }

    public void setUsername(String username) {
        Username = username;
    }

    public void setURI(String URI) {
        this.URI = URI;
    }

    public String getAction() {
        return Action;
    }

    public void setAction(String action) {
        Action = action;
    }

    public int getStatus() {
        return Status;
    }

    public void setStatus(int status) {
        Status = status;
    }
}
