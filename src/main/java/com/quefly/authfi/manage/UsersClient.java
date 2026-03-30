package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.Map;

/** User management API. */
public class UsersClient {

    private final AuthFIConfig config;
    private final HttpTransport http;

    public UsersClient(AuthFIConfig config, HttpTransport http) {
        this.config = config;
        this.http = http;
    }

    /** Create a user. */
    public String create(String email, Map<String, Object> properties) {
        var body = new java.util.HashMap<>(properties);
        body.put("email", email);
        return http.post("/users", body);
    }

    /** Get user by ID. */
    public String get(String userId) {
        return http.get("/users/" + userId);
    }

    /** List users with optional query params. */
    public String list() {
        return http.get("/users");
    }

    /** Update user. */
    public String update(String userId, Map<String, Object> properties) {
        return http.patch("/users/" + userId, properties);
    }

    /** Delete user. */
    public String delete(String userId) {
        return http.delete("/users/" + userId);
    }

    /** Assign roles to a user. */
    public String assignRoles(String userId, String... roleIds) {
        return http.post("/users/" + userId + "/roles", Map.of("roles", roleIds));
    }

    /** Add user to groups. */
    public String addToGroups(String userId, String... groupIds) {
        return http.post("/users/" + userId + "/groups", Map.of("groups", groupIds));
    }

    /** Block a user. */
    public String block(String userId) {
        return http.post("/users/" + userId + "/block", Map.of());
    }

    /** Unblock a user. */
    public String unblock(String userId) {
        return http.post("/users/" + userId + "/unblock", Map.of());
    }
}
