package com.quefly.authfi.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class AuthFIJwtAuthenticationConverterTest {

    private static Jwt jwt(java.util.function.Consumer<Jwt.Builder> claims) {
        Jwt.Builder b = Jwt.withTokenValue("test-token")
            .header("alg", "RS256")
            .subject("usr_1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(3600));
        claims.accept(b);
        return b.build();
    }

    @Test
    void mapsPermissionsClaimToAuthoritiesWithoutPrefix() {
        Jwt token = jwt(b -> b.claim("permissions", List.of("read:users", "write:users")));

        AbstractAuthenticationToken auth = new AuthFIJwtAuthenticationConverter().convert(token);
        Set<String> authorities = auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());

        assertTrue(authorities.contains("read:users"));
        assertTrue(authorities.contains("write:users"));
        assertFalse(authorities.stream().anyMatch(a -> a.startsWith("SCOPE_")));
    }

    @Test
    void mapsRolesClaimToRolePrefix() {
        Jwt token = jwt(b -> b.claim("roles", List.of("admin", "editor")));

        AbstractAuthenticationToken auth = new AuthFIJwtAuthenticationConverter().convert(token);
        Set<String> authorities = auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());

        assertTrue(authorities.contains("ROLE_admin"));
        assertTrue(authorities.contains("ROLE_editor"));
    }

    @Test
    void combinesPermissionsAndRoles() {
        Jwt token = jwt(b -> b
            .claim("permissions", List.of("read:users"))
            .claim("roles", List.of("admin")));

        AbstractAuthenticationToken auth = new AuthFIJwtAuthenticationConverter().convert(token);
        Set<String> authorities = auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());

        assertEquals(Set.of("read:users", "ROLE_admin"), authorities);
    }

    @Test
    void preservesSubjectAsPrincipalName() {
        Jwt token = jwt(b -> b.subject("usr_42").claim("permissions", List.of("read:x")));

        AbstractAuthenticationToken auth = new AuthFIJwtAuthenticationConverter().convert(token);

        assertEquals("usr_42", auth.getName());
    }

    @Test
    void tolerantOfMissingClaims() {
        Jwt token = jwt(b -> {}); // no permissions or roles

        AbstractAuthenticationToken auth = new AuthFIJwtAuthenticationConverter().convert(token);

        assertNotNull(auth);
        assertTrue(auth.getAuthorities().isEmpty());
    }
}
