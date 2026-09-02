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
        /** OAuth2 client_credentials grant against /{tenant}/v1/agents/token (agent identity). */
        AGENT_CREDENTIALS
    }

    /** JWKS URL for this tenant. */
    public String jwksUrl() {
        return "https://" + tenant + ".authfi.io/.well-known/jwks.json";
    }

    /** Issuer URL (the subdomain base used for OIDC discovery). */
    public String issuer() {
        return "https://" + tenant + ".authfi.io";
    }

    /**
     * The tenant's base on the shared API host.
     *
     * <p>The edge dispatch is {@code api.authfi.io/<slug>/<path>} — the SLUG COMES FIRST. Every
     * builder below had the slug and the version the other way round, so every URL this SDK
     * produced 404'd against a real deployment.
     */
    private String tenantBase() {
        return baseUrl + "/" + tenant;
    }

    /** Management API base — service-credentialed routes. */
    public String manageUrl() {
        // There is no /manage/ prefix on the platform; those routes are /v1/* like the rest.
        return tenantBase() + "/v1";
    }

    /** Path-based v1 base — end-user-bearer and public routes. */
    public String v1Url() {
        return tenantBase() + "/v1";
    }

    /** OAuth2 token endpoint for customer service identity. */
    public String tokenEndpoint() {
        // OAuth lives at the issuer ROOT under /oauth, not beneath /v1 (URL_SCHEME.md Kind 2).
        return tenantBase() + "/oauth/token";
    }

    /** Agent token endpoint (AAP — client_credentials with agent_id/agent_secret). */
    public String agentTokenEndpoint() {
        return v1Url() + "/agents/token";
    }
}
