package com.quefly.authfi;

/** Immutable configuration for AuthFI SDK. */
public record AuthFIConfig(
    String tenant,
    String apiKey,
    String clientId,
    String clientSecret,
    String baseUrl,
    AuthMode authMode
) {
    public enum AuthMode {
        API_KEY,
        CLIENT_CREDENTIALS
    }

    /** JWKS URL for this tenant. */
    public String jwksUrl() {
        return "https://" + tenant + ".authfi.app/.well-known/jwks.json";
    }

    /** Issuer URL for this tenant. */
    public String issuer() {
        return "https://" + tenant + ".authfi.app";
    }

    /** Management API base. */
    public String manageUrl() {
        return baseUrl + "/manage/v1/" + tenant;
    }

    /** OAuth2 token endpoint. */
    public String tokenEndpoint() {
        return baseUrl + "/v1/" + tenant + "/oauth/token";
    }
}
