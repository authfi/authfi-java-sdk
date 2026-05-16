package com.quefly.authfi.spring;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PreAuthorizeScannerTest {

    @Test
    void extractsHasAuthorityLiteral() {
        Set<String> out = new HashSet<>();
        PreAuthorizeScanner.extractInto("hasAuthority('read:users')", out);
        assertEquals(Set.of("read:users"), out);
    }

    @Test
    void extractsHasRoleLiteral() {
        Set<String> out = new HashSet<>();
        PreAuthorizeScanner.extractInto("hasRole('admin')", out);
        assertEquals(Set.of("admin"), out);
    }

    @Test
    void extractsHasAnyAuthorityMultipleLiterals() {
        Set<String> out = new HashSet<>();
        PreAuthorizeScanner.extractInto("hasAnyAuthority('read:users', 'write:users')", out);
        assertEquals(Set.of("read:users", "write:users"), out);
    }

    @Test
    void extractsCombinedSpel() {
        Set<String> out = new HashSet<>();
        PreAuthorizeScanner.extractInto(
            "hasAuthority('delete:users') and hasRole('admin')", out);
        assertEquals(Set.of("delete:users", "admin"), out);
    }

    @Test
    void supportsDoubleQuotes() {
        Set<String> out = new HashSet<>();
        PreAuthorizeScanner.extractInto("hasAuthority(\"read:billing\")", out);
        assertEquals(Set.of("read:billing"), out);
    }

    @Test
    void skipsDynamicExpressions() {
        Set<String> out = new HashSet<>();
        PreAuthorizeScanner.extractInto("hasAuthority(#requiredPermission)", out);
        assertTrue(out.isEmpty(), "variable args yield no literal");
    }

    @Test
    void tolerantOfNullAndBlank() {
        Set<String> out = new HashSet<>();
        assertDoesNotThrow(() -> PreAuthorizeScanner.extractInto(null, out));
        assertDoesNotThrow(() -> PreAuthorizeScanner.extractInto("", out));
        assertTrue(out.isEmpty());
    }
}
