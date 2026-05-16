package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

/**
 * Session lifecycle — both end-user self-service and admin per-user views.
 * Self-service routes ({@code /sessions/*}) take the user's Bearer token;
 * admin routes ({@code /manage/v1/{tenant}/users/{id}/sessions}) use service auth.
 */
public class SessionsClient {

    private final HttpTransport http;

    public SessionsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    // --- end-user self-service ---

    /** GET /sessions — list the caller's active sessions. */
    public String listMine(String userToken) {
        return http.getAsUser(userToken, "/sessions");
    }

    /** DELETE /sessions/{id} — revoke a specific session. */
    public String revokeMine(String userToken, String sessionId) {
        return http.deleteAsUser(userToken, "/sessions/" + sessionId);
    }

    /** POST /sessions/revoke-all — sign me out everywhere. */
    public String revokeAllMine(String userToken) {
        return http.postAsUser(userToken, "/sessions/revoke-all", java.util.Map.of());
    }

    // --- admin per-user ---

    /** GET /manage/v1/{tenant}/users/{id}/sessions. */
    public String listForUser(String userId) {
        return http.get("/users/" + userId + "/sessions");
    }

    /** POST /manage/v1/{tenant}/users/{id}/sessions/revoke. */
    public String revokeAllForUser(String userId) {
        return http.post("/users/" + userId + "/sessions/revoke", java.util.Map.of());
    }
}
