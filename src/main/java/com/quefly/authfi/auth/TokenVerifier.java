package com.quefly.authfi.auth;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.AuthFIException;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Verifies AuthFI JWTs using JWKS endpoint.
 * RS256 signature verification + issuer + expiry.
 */
public class TokenVerifier {

    private final AuthFIConfig config;
    private final JwkProvider jwkProvider;

    public TokenVerifier(AuthFIConfig config) {
        this.config = config;
        try {
            this.jwkProvider = new JwkProviderBuilder(URI.create(config.jwksUrl()).toURL())
                .cached(10, 24, TimeUnit.HOURS)
                .rateLimited(10, 1, TimeUnit.MINUTES)
                .build();
        } catch (java.net.MalformedURLException e) {
            throw new AuthFIException("Invalid JWKS URL: " + config.jwksUrl(), e);
        }
    }

    /** Verify a JWT string and return parsed claims. */
    public AuthFIClaims verify(String token) {
        try {
            DecodedJWT unverified = JWT.decode(token);
            String kid = unverified.getKeyId();
            if (kid == null) throw new AuthFIException("Token missing kid", 401);

            RSAPublicKey publicKey = (RSAPublicKey) jwkProvider.get(kid).getPublicKey();

            DecodedJWT verified = JWT.require(Algorithm.RSA256(publicKey, null))
                .withIssuer(config.issuer())
                .build()
                .verify(token);

            return AuthFIClaims.from(verified);
        } catch (AuthFIException e) {
            throw e;
        } catch (com.auth0.jwt.exceptions.TokenExpiredException e) {
            throw new AuthFIException("Token expired", 401);
        } catch (com.auth0.jwt.exceptions.JWTVerificationException e) {
            throw new AuthFIException("Token verification failed: " + e.getMessage(), 401);
        } catch (Exception e) {
            throw new AuthFIException("Token verification failed", 401);
        }
    }

    /** Verify from Authorization header value (Bearer xxx). */
    public AuthFIClaims verifyHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new AuthFIException("Missing or invalid Authorization header", 401);
        }
        return verify(authorizationHeader.substring(7));
    }

    /** Check that claims have ALL required permissions. */
    public void requirePermissions(AuthFIClaims claims, String... permissions) {
        for (String p : permissions) {
            if (!claims.permissions().contains(p)) {
                throw new AuthFIException("Missing permission: " + p, 403, "insufficient_permissions");
            }
        }
    }

    /** Check that claims have ANY of the required roles. */
    public void requireRole(AuthFIClaims claims, String... roles) {
        for (String r : roles) {
            if (claims.roles().contains(r)) return;
        }
        throw new AuthFIException("Insufficient role", 403, "insufficient_role");
    }

    /** Check that claims belong to a specific organization. */
    public void requireOrg(AuthFIClaims claims, String orgSlug) {
        if (!orgSlug.equals(claims.orgSlug())) {
            throw new AuthFIException("Not a member of organization: " + orgSlug, 403);
        }
    }
}
