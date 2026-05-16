package com.quefly.authfi.auth;

import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Parsed and verified AuthFI JWT claims. */
public record AuthFIClaims(
    String sub,
    String email,
    String name,
    boolean emailVerified,
    String tenantId,
    String orgId,
    String orgSlug,
    String orgRole,
    List<String> roles,
    List<String> permissions,
    List<String> groups,
    long iat,
    long exp,
    String issuer,
    Map<String, Object> raw
) {
    static AuthFIClaims from(JWTClaimsSet jwt) {
        return new AuthFIClaims(
            jwt.getSubject() != null ? jwt.getSubject() : "",
            str(jwt, "email"),
            str(jwt, "name"),
            bool(jwt, "email_verified"),
            str(jwt, "tenant_id"),
            str(jwt, "org_id"),
            str(jwt, "org_slug"),
            str(jwt, "org_role"),
            strList(jwt, "roles"),
            strList(jwt, "permissions"),
            strList(jwt, "groups"),
            jwt.getIssueTime() != null ? jwt.getIssueTime().toInstant().getEpochSecond() : 0,
            jwt.getExpirationTime() != null ? jwt.getExpirationTime().toInstant().getEpochSecond() : 0,
            jwt.getIssuer() != null ? jwt.getIssuer() : "",
            Collections.unmodifiableMap(jwt.getClaims())
        );
    }

    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    public boolean inGroup(String group) {
        return groups.contains(group);
    }

    public boolean inOrg(String slug) {
        return slug.equals(orgSlug);
    }

    private static String str(JWTClaimsSet jwt, String key) {
        try {
            String v = jwt.getStringClaim(key);
            return v != null ? v : "";
        } catch (ParseException e) {
            return "";
        }
    }

    private static boolean bool(JWTClaimsSet jwt, String key) {
        try {
            Boolean v = jwt.getBooleanClaim(key);
            return Boolean.TRUE.equals(v);
        } catch (ParseException e) {
            return false;
        }
    }

    private static List<String> strList(JWTClaimsSet jwt, String key) {
        try {
            List<String> v = jwt.getStringListClaim(key);
            return v != null ? Collections.unmodifiableList(v) : Collections.emptyList();
        } catch (ParseException e) {
            return Collections.emptyList();
        }
    }
}
