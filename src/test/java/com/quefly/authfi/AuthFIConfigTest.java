package com.quefly.authfi;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthFIConfigTest {

    @Test
    void jwksUrl() {
        var config = new AuthFIConfig("acme", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        assertEquals("https://acme.authfi.io/.well-known/jwks.json", config.jwksUrl());
    }

    @Test
    void issuer() {
        var config = new AuthFIConfig("acme", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        assertEquals("https://acme.authfi.io", config.issuer());
    }

    @Test
    void manageUrl() {
        var config = new AuthFIConfig("acme", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        // The edge dispatch is /<slug>/<path> — slug FIRST — and there is no /manage/ prefix.
        assertEquals("https://api.authfi.io/acme/v1", config.manageUrl());
    }

    @Test
    void tokenEndpoint() {
        var config = new AuthFIConfig("acme", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        // OAuth is at the issuer root under /oauth, never beneath /v1.
        assertEquals("https://api.authfi.io/acme/oauth/token", config.tokenEndpoint());
    }

    @Test
    void v1Url() {
        var config = new AuthFIConfig("acme", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        assertEquals("https://api.authfi.io/acme/v1", config.v1Url());
    }
}
