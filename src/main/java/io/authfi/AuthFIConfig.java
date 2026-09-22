package io.authfi;

/** Immutable configuration for AuthFI SDK. */
public record AuthFIConfig(
    String tenant,
    String apiKey,
    String clientId,
    String clientSecret,
    String agentId,
    String agentSecret,
    /**
     * The agent's own Ed25519 private key, PKCS#8 PEM. When present the SDK authenticates with
     * RFC 7523 private_key_jwt and {@link #agentSecret()} is not used.
     *
     * <p>This is the method the platform advertises; registering an agent with a public JWK issues
     * no secret at all, so a key-registered agent has nothing else to present.
     */
    String agentPrivateKey,
    /** The {@code kid} registered alongside the public JWK. Required with {@link #agentPrivateKey()}. */
    String agentKeyId,
    String baseUrl,
    AuthMode authMode
) {
    /**
     * The pre-key constructor, kept so existing callers still compile.
     *
     * <p>An agent built this way authenticates with a secret, which works only for a legacy agent
     * whose record holds one.
     */
    public AuthFIConfig(String tenant, String apiKey, String clientId, String clientSecret,
                        String agentId, String agentSecret, String baseUrl, AuthMode authMode) {
        this(tenant, apiKey, clientId, clientSecret, agentId, agentSecret, null, null, baseUrl, authMode);
    }

    /** True when this config can authenticate an agent by signing rather than by echoing a secret. */
    public boolean hasAgentKey() {
        return agentPrivateKey != null && !agentPrivateKey.isBlank()
            && agentKeyId != null && !agentKeyId.isBlank();
    }

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
