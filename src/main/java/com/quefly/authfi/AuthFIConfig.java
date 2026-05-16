package com.quefly.authfi;

/** Immutable configuration for AuthFI SDK. */
public record AuthFIConfig(
    String tenant,
    String apiKey,
    String clientId,
    String clientSecret,
    String agentId,
    String agentSecret,
    String baseUrl,
    AuthMode authMode
) {
    public enum AuthMode {
        /** X-API-Key header on management calls. */
        API_KEY,
        /** OAuth2 client_credentials grant (customer service identity). */
        CLIENT_CREDENTIALS,
        /** OAuth2 client_credentials grant against /v1/{tenant}/agents/token (agent identity). */
        AGENT_CREDENTIALS
    }

    /** JWKS URL for this tenant. */
    public String jwksUrl() {
        return "https://" + tenant + ".authfi.app/.well-known/jwks.json";
    }

    /** Issuer URL (the subdomain base used for OIDC discovery). */
    public String issuer() {
        return "https://" + tenant + ".authfi.app";
    }

    /** Management API base — service-credentialed routes. */
    public String manageUrl() {
        return baseUrl + "/manage/v1/" + tenant;
    }

    /** Path-based v1 base — end-user-bearer and public routes. */
    public String v1Url() {
        return baseUrl + "/v1/" + tenant;
    }

    /** OAuth2 token endpoint for customer service identity. */
    public String tokenEndpoint() {
        return v1Url() + "/oauth/token";
    }

    /** Agent token endpoint (AAP — client_credentials with agent_id/agent_secret). */
    public String agentTokenEndpoint() {
        return v1Url() + "/agents/token";
    }
}
