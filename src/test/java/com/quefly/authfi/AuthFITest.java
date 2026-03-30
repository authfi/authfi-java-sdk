package com.quefly.authfi;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthFITest {

    @Test
    void clientBuilderRequiresTenant() {
        assertThrows(IllegalArgumentException.class, () ->
            AuthFI.client().apiKey("sk_test").build()
        );
    }

    @Test
    void clientBuilderRequiresApiKey() {
        assertThrows(IllegalArgumentException.class, () ->
            AuthFI.client().tenant("acme").build()
        );
    }

    @Test
    void serviceBuilderRequiresClientCredentials() {
        assertThrows(IllegalArgumentException.class, () ->
            AuthFI.service().tenant("acme").build()
        );
    }

    @Test
    void serviceBuilderRequiresBothIdAndSecret() {
        assertThrows(IllegalArgumentException.class, () ->
            AuthFI.service().tenant("acme").clientId("id").build()
        );
    }

    @Test
    void clientBuilderCreatesInstance() {
        AuthFI authfi = AuthFI.client()
            .tenant("acme")
            .apiKey("sk_test_123")
            .build();

        assertNotNull(authfi);
        assertEquals("acme", authfi.getConfig().tenant());
        assertEquals("sk_test_123", authfi.getConfig().apiKey());
        assertEquals(AuthFIConfig.AuthMode.API_KEY, authfi.getConfig().authMode());
    }

    @Test
    void serviceBuilderCreatesInstance() {
        AuthFI authfi = AuthFI.service()
            .tenant("acme")
            .clientId("FIC-abc123")
            .clientSecret("FIS-xyz789")
            .build();

        assertNotNull(authfi);
        assertEquals(AuthFIConfig.AuthMode.CLIENT_CREDENTIALS, authfi.getConfig().authMode());
        assertEquals("FIC-abc123", authfi.getConfig().clientId());
    }

    @Test
    void customBaseUrl() {
        AuthFI authfi = AuthFI.client()
            .tenant("acme")
            .apiKey("sk_test")
            .baseUrl("https://custom.api.com")
            .build();

        assertEquals("https://custom.api.com", authfi.getConfig().baseUrl());
    }

    @Test
    void modulesAreLazilyInitialized() {
        AuthFI authfi = AuthFI.client()
            .tenant("acme")
            .apiKey("sk_test")
            .build();

        // Modules should be accessible
        assertNotNull(authfi.auth());
        assertNotNull(authfi.connect());
        assertNotNull(authfi.users());
        assertNotNull(authfi.orgs());
        assertNotNull(authfi.permissions());
    }

    @Test
    void sameModuleInstanceReturnedOnMultipleCalls() {
        AuthFI authfi = AuthFI.client()
            .tenant("acme")
            .apiKey("sk_test")
            .build();

        assertSame(authfi.auth(), authfi.auth());
        assertSame(authfi.connect(), authfi.connect());
        assertSame(authfi.users(), authfi.users());
    }
}
