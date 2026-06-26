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
        assertEquals("https://api.authfi.io/manage/v1/acme", config.manageUrl());
    }

    @Test
    void tokenEndpoint() {
        var config = new AuthFIConfig("acme", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        assertEquals("https://api.authfi.io/v1/acme/oauth/token", config.tokenEndpoint());
    }

    @Test
    void v1Url() {
        var config = new AuthFIConfig("acme", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        assertEquals("https://api.authfi.io/v1/acme", config.v1Url());
    }
}
