package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.Map;

/**
 * Current-user endpoints. Caller passes the end-user's access token.
 * Backed by /v1/{tenant}/me/* in authfi-auth-service.
 */
public class MeClient {

    private final HttpTransport http;

    public MeClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    /** GET /me — full profile (roles, permissions, last_login_at, sessions). */
    public String get(String userToken) {
        return http.getAsUser(userToken, "/me");
    }

    /** GET /userinfo — OIDC standard claims (sub, email, org_id, ...). */
    public String userinfo(String userToken) {
        return http.getAsUser(userToken, "/userinfo");
    }

    /** POST /me/password — change own password. */
    public String changePassword(String userToken, String currentPassword, String newPassword) {
        return http.postAsUser(userToken, "/me/password", Map.of(
            "current_password", currentPassword,
            "new_password", newPassword
        ));
    }

    /** GET /me/security-score. */
    public String securityScore(String userToken) {
        return http.getAsUser(userToken, "/me/security-score");
    }
}
