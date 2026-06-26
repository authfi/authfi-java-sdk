package com.quefly.authfi.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.AuthFIException;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TokenVerifierTest {

    private static AuthFIConfig testConfig() {
        return new AuthFIConfig("test", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
    }

    private static AuthFIClaims claimsFor(JWTClaimsSet set) throws Exception {
        RSAKey rsa = new RSAKeyGenerator(2048).keyID("test").generate();
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsa.getKeyID()).build(),
            set
        );
        jwt.sign(new RSASSASigner(rsa));
        return AuthFIClaims.from(SignedJWT.parse(jwt.serialize()).getJWTClaimsSet());
    }

    @Test
    void rejectsNullAuthHeader() {
        var verifier = new TokenVerifier(testConfig());

        var ex = assertThrows(AuthFIException.class, () -> verifier.verifyHeader(null));
        assertEquals(401, ex.getStatus());
    }

    @Test
    void rejectsInvalidAuthHeader() {
        var verifier = new TokenVerifier(testConfig());

        var ex = assertThrows(AuthFIException.class, () -> verifier.verifyHeader("Basic abc123"));
        assertEquals(401, ex.getStatus());
    }

    @Test
    void rejectsInvalidToken() {
        var verifier = new TokenVerifier(testConfig());

        var ex = assertThrows(AuthFIException.class, () -> verifier.verify("not.a.token"));
        assertEquals(401, ex.getStatus());
    }

    @Test
    void rejectsEmptyToken() {
        var verifier = new TokenVerifier(testConfig());

        var ex = assertThrows(AuthFIException.class, () -> verifier.verify(""));
        assertEquals(401, ex.getStatus());
    }

    @Test
    void requirePermissionsThrowsOnMissing() throws Exception {
        AuthFIClaims claims = claimsFor(new JWTClaimsSet.Builder()
            .subject("usr_1")
            .claim("permissions", List.of("read:users"))
            .issuer("https://test.authfi.io")
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
            .build());

        var verifier = new TokenVerifier(testConfig());

        assertDoesNotThrow(() -> verifier.requirePermissions(claims, "read:users"));

        var ex = assertThrows(AuthFIException.class,
            () -> verifier.requirePermissions(claims, "delete:users"));
        assertEquals(403, ex.getStatus());
    }

    @Test
    void requireRoleThrowsOnMissing() throws Exception {
        AuthFIClaims claims = claimsFor(new JWTClaimsSet.Builder()
            .subject("usr_1")
            .claim("roles", List.of("editor"))
            .issuer("https://test.authfi.io")
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
            .build());

        var verifier = new TokenVerifier(testConfig());

        assertDoesNotThrow(() -> verifier.requireRole(claims, "editor"));

        var ex = assertThrows(AuthFIException.class,
            () -> verifier.requireRole(claims, "admin"));
        assertEquals(403, ex.getStatus());
    }
}
