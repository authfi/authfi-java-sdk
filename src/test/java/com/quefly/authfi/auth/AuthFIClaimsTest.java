package com.quefly.authfi.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AuthFIClaimsTest {

    private static JWTClaimsSet parse(String token) throws ParseException {
        return SignedJWT.parse(token).getJWTClaimsSet();
    }

    private static String sign(JWTClaimsSet claims) throws JOSEException {
        RSAKey rsa = new RSAKeyGenerator(2048).keyID("test").generate();
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsa.getKeyID()).build(),
            claims
        );
        jwt.sign(new RSASSASigner(rsa));
        return jwt.serialize();
    }

    @Test
    void parsesClaimsFromJwt() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
            .subject("usr_123")
            .claim("email", "jane@acme.com")
            .claim("name", "Jane Smith")
            .claim("email_verified", true)
            .claim("tenant_id", "tnt_456")
            .claim("org_id", "org_789")
            .claim("org_slug", "acme-corp")
            .claim("org_role", "admin")
            .claim("roles", List.of("admin", "editor"))
            .claim("permissions", List.of("read:users", "write:users"))
            .claim("groups", List.of("engineering"))
            .issuer("https://acme.authfi.app")
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
            .build());

        AuthFIClaims claims = AuthFIClaims.from(parse(token));

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
        String token = sign(new JWTClaimsSet.Builder()
            .subject("usr_1")
            .claim("permissions", List.of("read:users", "write:users"))
            .claim("roles", List.of("admin"))
            .issuer("https://test.authfi.app")
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
            .build());

        AuthFIClaims claims = AuthFIClaims.from(parse(token));

        assertTrue(claims.hasPermission("read:users"));
        assertTrue(claims.hasPermission("write:users"));
        assertFalse(claims.hasPermission("delete:users"));
    }

    @Test
    void hasRole() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
            .subject("usr_1")
            .claim("roles", List.of("admin", "editor"))
            .issuer("https://test.authfi.app")
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
            .build());

        AuthFIClaims claims = AuthFIClaims.from(parse(token));

        assertTrue(claims.hasRole("admin"));
        assertTrue(claims.hasRole("editor"));
        assertFalse(claims.hasRole("viewer"));
    }

    @Test
    void inOrg() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
            .subject("usr_1")
            .claim("org_slug", "acme-corp")
            .issuer("https://test.authfi.app")
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
            .build());

        AuthFIClaims claims = AuthFIClaims.from(parse(token));

        assertTrue(claims.inOrg("acme-corp"));
        assertFalse(claims.inOrg("other-org"));
    }

    @Test
    void handlesEmptyClaims() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
            .subject("usr_1")
            .issuer("https://test.authfi.app")
            .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
            .build());

        AuthFIClaims claims = AuthFIClaims.from(parse(token));

        assertEquals("usr_1", claims.sub());
        assertEquals("", claims.email());
        assertTrue(claims.roles().isEmpty());
        assertTrue(claims.permissions().isEmpty());
        assertTrue(claims.groups().isEmpty());
    }
}
