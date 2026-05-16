package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.Map;

/**
 * MFA enrollment / verification — TOTP today, WebAuthn / SMS to follow.
 * All routes take the end-user's Bearer token.
 */
public class MFAClient {

    private final HttpTransport http;

    public MFAClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    /** POST /mfa/enroll — start TOTP enrollment, returns secret + otpauth URI + backup-code hint. */
    public String enroll(String userToken) {
        return http.postAsUser(userToken, "/mfa/enroll", Map.of());
    }

    /**
     * POST /mfa/verify — finalize enrollment by submitting a TOTP code from the authenticator.
     * Backup codes are returned in the response and shown ONCE.
     */
    public String verify(String userToken, String factorId, String code) {
        return http.postAsUser(userToken, "/mfa/verify", Map.of(
            "factor_id", factorId,
            "code", code
        ));
    }

    /** GET /mfa/factors — list the caller's enrolled factors (no secrets exposed). */
    public String listFactors(String userToken) {
        return http.getAsUser(userToken, "/mfa/factors");
    }

    /** POST /mfa/unenroll — remove a factor (requires a current TOTP code to confirm). */
    public String unenroll(String userToken, String factorId, String code) {
        return http.postAsUser(userToken, "/mfa/unenroll", Map.of(
            "factor_id", factorId,
            "code", code
        ));
    }
}
