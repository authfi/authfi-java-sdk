package com.quefly.authfi.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AuthFIClaimsTest {

    @Test
    void parsesClaimsFromJwt() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Algorithm algo = Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate());

        String token = JWT.create()
            .withSubject("usr_123")
            .withClaim("email", "jane@acme.com")
            .withClaim("name", "Jane Smith")
            .withClaim("email_verified", true)
            .withClaim("tenant_id", "tnt_456")
            .withClaim("org_id", "org_789")
            .withClaim("org_slug", "acme-corp")
            .withClaim("org_role", "admin")
            .withClaim("roles", List.of("admin", "editor"))
            .withClaim("permissions", List.of("read:users", "write:users"))
            .withClaim("groups", List.of("engineering"))
            .withIssuer("https://acme.authfi.app")
            .withIssuedAt(Instant.now())
            .withExpiresAt(Instant.now().plusSeconds(3600))
            .sign(algo);

        var decoded = JWT.require(algo).withIssuer("https://acme.authfi.app").build().verify(token);
        AuthFIClaims claims = AuthFIClaims.from(decoded);

        assertEquals("usr_123", claims.sub());
        assertEquals("jane@acme.com", claims.email());
        assertEquals("Jane Smith", claims.name());
        assertTrue(claims.emailVerified());
        assertEquals("tnt_456", claims.tenantId());
        assertEquals("org_789", claims.orgId());
        assertEquals("acme-corp", claims.orgSlug());
        assertEquals("admin", claims.orgRole());
        assertEquals(List.of("admin", "editor"), claims.roles());
        assertEquals(List.of("read:users", "write:users"), claims.permissions());
        assertEquals(List.of("engineering"), claims.groups());
        assertEquals("https://acme.authfi.app", claims.issuer());
    }

    @Test
    void hasPermission() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Algorithm algo = Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate());

        String token = JWT.create()
            .withSubject("usr_1")
            .withClaim("permissions", List.of("read:users", "write:users"))
            .withClaim("roles", List.of("admin"))
            .withIssuer("https://test.authfi.app")
            .withExpiresAt(Instant.now().plusSeconds(3600))
            .sign(algo);

        var decoded = JWT.require(algo).withIssuer("https://test.authfi.app").build().verify(token);
        AuthFIClaims claims = AuthFIClaims.from(decoded);

        assertTrue(claims.hasPermission("read:users"));
        assertTrue(claims.hasPermission("write:users"));
        assertFalse(claims.hasPermission("delete:users"));
    }

    @Test
    void hasRole() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Algorithm algo = Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate());

        String token = JWT.create()
            .withSubject("usr_1")
            .withClaim("roles", List.of("admin", "editor"))
            .withIssuer("https://test.authfi.app")
            .withExpiresAt(Instant.now().plusSeconds(3600))
            .sign(algo);

        var decoded = JWT.require(algo).withIssuer("https://test.authfi.app").build().verify(token);
        AuthFIClaims claims = AuthFIClaims.from(decoded);

        assertTrue(claims.hasRole("admin"));
        assertTrue(claims.hasRole("editor"));
        assertFalse(claims.hasRole("viewer"));
    }

    @Test
    void inOrg() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Algorithm algo = Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate());

        String token = JWT.create()
            .withSubject("usr_1")
            .withClaim("org_slug", "acme-corp")
            .withIssuer("https://test.authfi.app")
            .withExpiresAt(Instant.now().plusSeconds(3600))
            .sign(algo);

        var decoded = JWT.require(algo).withIssuer("https://test.authfi.app").build().verify(token);
        AuthFIClaims claims = AuthFIClaims.from(decoded);

        assertTrue(claims.inOrg("acme-corp"));
        assertFalse(claims.inOrg("other-org"));
    }

    @Test
    void handlesEmptyClaims() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Algorithm algo = Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate());

        String token = JWT.create()
            .withSubject("usr_1")
            .withIssuer("https://test.authfi.app")
            .withExpiresAt(Instant.now().plusSeconds(3600))
            .sign(algo);

        var decoded = JWT.require(algo).withIssuer("https://test.authfi.app").build().verify(token);
        AuthFIClaims claims = AuthFIClaims.from(decoded);

        assertEquals("usr_1", claims.sub());
        assertEquals("", claims.email());
        assertTrue(claims.roles().isEmpty());
        assertTrue(claims.permissions().isEmpty());
        assertTrue(claims.groups().isEmpty());
    }
}
