package com.quefly.authfi.auth;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.AuthFIException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenVerifierTest {

    @Test
    void rejectsNullAuthHeader() {
        var config = new AuthFIConfig("test", "sk_test", null, null,
            "https://api.authfi.app", AuthFIConfig.AuthMode.API_KEY);
        var verifier = new TokenVerifier(config);

        var ex = assertThrows(AuthFIException.class, () ->
            verifier.verifyHeader(null)
        );
        assertEquals(401, ex.getStatus());
    }

    @Test
    void rejectsInvalidAuthHeader() {
        var config = new AuthFIConfig("test", "sk_test", null, null,
            "https://api.authfi.app", AuthFIConfig.AuthMode.API_KEY);
        var verifier = new TokenVerifier(config);

        var ex = assertThrows(AuthFIException.class, () ->
            verifier.verifyHeader("Basic abc123")
        );
        assertEquals(401, ex.getStatus());
    }

    @Test
    void rejectsInvalidToken() {
        var config = new AuthFIConfig("test", "sk_test", null, null,
            "https://api.authfi.app", AuthFIConfig.AuthMode.API_KEY);
        var verifier = new TokenVerifier(config);

        var ex = assertThrows(AuthFIException.class, () ->
            verifier.verify("not.a.token")
        );
        assertEquals(401, ex.getStatus());
    }

    @Test
    void requirePermissionsThrowsOnMissing() throws Exception {
        var kp = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var algo = com.auth0.jwt.algorithms.Algorithm.RSA256(
            (java.security.interfaces.RSAPublicKey) kp.getPublic(),
            (java.security.interfaces.RSAPrivateKey) kp.getPrivate()
        );

        String token = com.auth0.jwt.JWT.create()
            .withSubject("usr_1")
            .withClaim("permissions", java.util.List.of("read:users"))
            .withIssuer("https://test.authfi.app")
            .withExpiresAt(java.time.Instant.now().plusSeconds(3600))
            .sign(algo);

        var decoded = com.auth0.jwt.JWT.require(algo)
            .withIssuer("https://test.authfi.app").build().verify(token);
        AuthFIClaims claims = AuthFIClaims.from(decoded);

        var config = new AuthFIConfig("test", "sk_test", null, null,
            "https://api.authfi.app", AuthFIConfig.AuthMode.API_KEY);
        var verifier = new TokenVerifier(config);

        // Should not throw — has the permission
        assertDoesNotThrow(() -> verifier.requirePermissions(claims, "read:users"));

        // Should throw — missing permission
        var ex = assertThrows(AuthFIException.class, () ->
            verifier.requirePermissions(claims, "delete:users")
        );
        assertEquals(403, ex.getStatus());
    }

    @Test
    void requireRoleThrowsOnMissing() throws Exception {
        var kp = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var algo = com.auth0.jwt.algorithms.Algorithm.RSA256(
            (java.security.interfaces.RSAPublicKey) kp.getPublic(),
            (java.security.interfaces.RSAPrivateKey) kp.getPrivate()
        );

        String token = com.auth0.jwt.JWT.create()
            .withSubject("usr_1")
            .withClaim("roles", java.util.List.of("editor"))
            .withIssuer("https://test.authfi.app")
            .withExpiresAt(java.time.Instant.now().plusSeconds(3600))
            .sign(algo);

        var decoded = com.auth0.jwt.JWT.require(algo)
            .withIssuer("https://test.authfi.app").build().verify(token);
        AuthFIClaims claims = AuthFIClaims.from(decoded);

        var config = new AuthFIConfig("test", "sk_test", null, null,
            "https://api.authfi.app", AuthFIConfig.AuthMode.API_KEY);
        var verifier = new TokenVerifier(config);

        assertDoesNotThrow(() -> verifier.requireRole(claims, "editor"));

        var ex = assertThrows(AuthFIException.class, () ->
            verifier.requireRole(claims, "admin")
        );
        assertEquals(403, ex.getStatus());
    }
}
