package com.quefly.authfi.token;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.AuthFIException;
import com.quefly.authfi.HttpTransport;

/**
 * Public .well-known discovery — OIDC, JWKS, SMART on FHIR, AuthFI Agent Protocol.
 * Served from the tenant subdomain ({@code https://{tenant}.authfi.io}).
 */
public class DiscoveryClient {

    private final AuthFIConfig config;
    private final HttpTransport http;

    public DiscoveryClient(AuthFIConfig config, HttpTransport http) {
        this.config = config;
        this.http = http;
    }

    /** GET /.well-known/openid-configuration. */
    public String openidConfiguration() {
        return http.getAnonymous(config.issuer() + "/.well-known/openid-configuration");
    }

    /** GET /.well-known/jwks.json — the JWKS Nimbus already pulls under the hood. */
    public String jwks() {
        return http.getAnonymous(config.issuer() + "/.well-known/jwks.json");
    }

    /**
     * GET /.well-known/smart-configuration — SMART on FHIR discovery.
     * Returns {@code null} on 404 (tenant has no healthcare module).
     */
    public String smartConfiguration() {
        try {
            return http.getAnonymous(config.issuer() + "/.well-known/smart-configuration");
        } catch (AuthFIException e) {
            if (e.getStatus() == 404) return null;
            throw e;
        }
    }

    /** GET /.well-known/agent-auth — AuthFI Agent Protocol discovery. */
    public String agentAuth() {
        return http.getAnonymous(config.issuer() + "/.well-known/agent-auth");
    }
}
