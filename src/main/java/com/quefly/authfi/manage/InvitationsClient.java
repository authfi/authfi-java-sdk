package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

/**
 * Programmatic user invitations.
 *
 * <p><b>Status:</b> the backend routes (/manage/{tenant}/v1/invitations/*) are not yet
 * wired in authfi-auth-service / authfi-admin-service as of 2026-05-16. Calling these
 * methods today will receive an HTTP error from the server.
 *
 * <p>Track the platform task: "Wire /manage/{tenant}/v1/invitations/* routes"
 * (memex mx_361aacd). This client will work transparently once the routes ship.
 */
public class InvitationsClient {

    private final HttpTransport http;

    public InvitationsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    /** POST /manage/{tenant}/v1/invitations — create an invitation. */
    public String create(String email, String orgId, String role) {
        return http.post("/invitations", java.util.Map.of(
            "email", email,
            "org_id", orgId,
            "role", role
        ));
    }

    /** GET /manage/{tenant}/v1/invitations — list. */
    public String list() {
        return http.get("/invitations");
    }

    /** GET /manage/{tenant}/v1/invitations/{id}. */
    public String get(String invitationId) {
        return http.get("/invitations/" + invitationId);
    }

    /** DELETE /manage/{tenant}/v1/invitations/{id} — revoke. */
    public String revoke(String invitationId) {
        return http.delete("/invitations/" + invitationId);
    }

    /** POST /manage/{tenant}/v1/invitations/{id}/resend. */
    public String resend(String invitationId) {
        return http.post("/invitations/" + invitationId + "/resend", java.util.Map.of());
    }
}
