package com.quefly.authfi.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.AuthFIException;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

/**
 * Verifies AuthFI JWTs using JWKS endpoint.
 * RS256 signature verification + issuer + expiry, backed by Nimbus.
 */
public class TokenVerifier {

    private final AuthFIConfig config;
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public TokenVerifier(AuthFIConfig config) {
        this.config = config;
        try {
            URL jwksUrl = new URL(config.jwksUrl());
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                .create(jwksUrl)
                .retrying(true)
                .build();

            JWSVerificationKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(keySelector);

            JWTClaimsSet expected = new JWTClaimsSet.Builder()
                .issuer(config.issuer())
                .build();
            Set<String> required = new HashSet<>();
            required.add("sub");
            required.add("exp");
            processor.setJWTClaimsSetVerifier(
                new DefaultJWTClaimsVerifier<>(expected, required)
            );

            this.jwtProcessor = processor;
        } catch (MalformedURLException e) {
            throw new AuthFIException("Invalid JWKS URL: " + config.jwksUrl(), e);
        }
    }

    /** Verify a JWT string and return parsed claims. */
    public AuthFIClaims verify(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthFIException("Empty token", 401);
        }
        try {
            JWTClaimsSet claims = jwtProcessor.process(token, null);
            return AuthFIClaims.from(claims);
        } catch (AuthFIException e) {
            throw e;
        } catch (com.nimbusds.jwt.proc.BadJWTException e) {
            throw new AuthFIException("Token verification failed: " + e.getMessage(), 401);
        } catch (com.nimbusds.jose.proc.BadJOSEException e) {
            throw new AuthFIException("Token verification failed: " + e.getMessage(), 401);
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new AuthFIException("Token verification failed: " + e.getMessage(), 401);
        } catch (java.text.ParseException e) {
            throw new AuthFIException("Malformed token: " + e.getMessage(), 401);
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
