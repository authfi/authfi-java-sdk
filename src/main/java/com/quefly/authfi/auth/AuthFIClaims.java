package com.quefly.authfi.auth;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Collections;
import java.util.List;

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
    DecodedJWT raw
) {
    /** Build from a verified DecodedJWT. */
    static AuthFIClaims from(DecodedJWT jwt) {
        return new AuthFIClaims(
            str(jwt, "sub"),
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
            jwt.getIssuedAtAsInstant() != null ? jwt.getIssuedAtAsInstant().getEpochSecond() : 0,
            jwt.getExpiresAtAsInstant() != null ? jwt.getExpiresAtAsInstant().getEpochSecond() : 0,
            jwt.getIssuer(),
            jwt
        );
    }

    /** Check if the user has a specific permission. */
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    /** Check if the user has a specific role. */
    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    /** Check if the user belongs to a specific group. */
    public boolean inGroup(String group) {
        return groups.contains(group);
    }

    /** Check if the user is in a specific org. */
    public boolean inOrg(String slug) {
        return slug.equals(orgSlug);
    }

    private static String str(DecodedJWT jwt, String key) {
        Claim c = jwt.getClaim(key);
        return c.isMissing() ? "" : c.asString();
    }

    private static boolean bool(DecodedJWT jwt, String key) {
        Claim c = jwt.getClaim(key);
        return !c.isMissing() && Boolean.TRUE.equals(c.asBoolean());
    }

    private static List<String> strList(DecodedJWT jwt, String key) {
        Claim c = jwt.getClaim(key);
        if (c.isMissing()) return Collections.emptyList();
        List<String> list = c.asList(String.class);
        return list != null ? Collections.unmodifiableList(list) : Collections.emptyList();
    }
}
