package io.authfi.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.authfi.AuthFIConfig;
import io.authfi.AuthFIException;

import java.net.MalformedURLException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verifies AuthFI access tokens against the issuer's JWKS.
 *
 * <p>Strict by construction. A token is accepted only when all of these hold:
 * <ul>
 *   <li>it is a compact JWS of three parts, at most 16 KiB, signed with EdDSA, ES256, PS256 or
 *       RS256 by the key its {@code kid} names, and that key suits the algorithm;</li>
 *   <li>its {@code typ} is {@code at+jwt} (RFC 9068), which refuses an ID token, a transaction
 *       token or a security event token offered as a bearer;</li>
 *   <li>{@code iss} equals the configured issuer, {@code aud} contains a configured audience,
 *       {@code exp} is present and in the future, {@code sub} and {@code tenant_id} are present;</li>
 *   <li>it is not sender-constrained ({@code cnf}, {@code authfi_mandate}), because a bearer
 *       presentation of such a token is a replay.</li>
 * </ul>
 * The audience is required: a verifier with no audience would accept a token minted for any other
 * API on the same issuer. Every refusal is an {@link AuthFIException} with status 401 and a
 * {@code token_*} code from the platform's vocabulary.
 */
public class TokenVerifier {

    private static final Set<String> ALGORITHMS = Set.of("EdDSA", "ES256", "PS256", "RS256");
    private static final int MAX_TOKEN_CHARS = 16 * 1024;
    private static final Duration DEFAULT_LEEWAY = Duration.ofSeconds(60);
    private static final Duration MAX_LEEWAY = Duration.ofSeconds(300);
    private static final Set<String> FIRST_PARTY_AUDIENCES = Set.of("authfi-console", "authfi-workspace");

    private final AuthFIConfig config;
    private final List<String> audiences;
    private final String expectedTenantId;
    private final long leewayMillis;
    private final JWKSource<SecurityContext> keys;

    /** Verifies tokens for the given API audience(s) against the tenant's published keys. */
    public TokenVerifier(AuthFIConfig config, String... audiences) {
        this(builder(config).audience(audiences));
    }

    private TokenVerifier(Builder b) {
        this.config = b.config;
        this.audiences = List.copyOf(b.audiences);
        this.expectedTenantId = b.expectedTenantId;
        this.leewayMillis = b.leeway.toMillis();
        if (audiences.isEmpty()) {
            throw new IllegalArgumentException(
                "A verifier needs the audience(s) of the API it protects. Without one it would accept "
                    + "a token minted for any other API on this issuer.");
        }
        for (String a : audiences) {
            refuseAuthFiAudience(a);
        }
        this.keys = b.keys != null ? b.keys : remoteKeys(b.config);
    }

    public static Builder builder(AuthFIConfig config) {
        return new Builder(config);
    }

    /** Configures a {@link TokenVerifier}. */
    public static final class Builder {
        private final AuthFIConfig config;
        private final List<String> audiences = new ArrayList<>();
        private String expectedTenantId;
        private Duration leeway = DEFAULT_LEEWAY;
        private JWKSource<SecurityContext> keys;

        private Builder(AuthFIConfig config) {
            this.config = config;
        }

        /** The audience(s) of the API being protected; a token must name one of them. */
        public Builder audience(String... values) {
            for (String v : values) {
                if (v != null && !v.isBlank()) audiences.add(v);
            }
            return this;
        }

        /** Pins the {@code tenant_id} claim. Set it when this server trusts more than one issuer. */
        public Builder expectedTenantId(String tenantId) {
            this.expectedTenantId = tenantId;
            return this;
        }

        /** Clock skew allowed on exp, nbf and iat, 0 to 5 minutes. Default 60 seconds. */
        public Builder leeway(Duration value) {
            if (value.isNegative() || value.compareTo(MAX_LEEWAY) > 0) {
                throw new IllegalArgumentException("leeway must be between 0 and 5 minutes");
            }
            this.leeway = value;
            return this;
        }

        /** Verifies against the given keys instead of the tenant's JWKS endpoint. */
        Builder keys(JWKSource<SecurityContext> source) {
            this.keys = source;
            return this;
        }

        public TokenVerifier build() {
            return new TokenVerifier(this);
        }
    }

    private void refuseAuthFiAudience(String audience) {
        String issuer = config.issuer();
        String base = config.baseUrl();
        boolean own = audience.equals(issuer) || audience.startsWith(issuer + "/")
            || (base != null && (audience.equals(base) || audience.startsWith(base + "/")))
            || FIRST_PARTY_AUDIENCES.contains(audience);
        if (own) {
            throw new IllegalArgumentException(
                "The audience '" + audience + "' is AuthFI's own. Tokens minted for the gateway carry it, so "
                    + "accepting it would let them be replayed at your API. Mint the token with "
                    + "resource=<your API's client id> and verify that audience.");
        }
    }

    private static JWKSource<SecurityContext> remoteKeys(AuthFIConfig config) {
        try {
            return JWKSourceBuilder
                .create(URI.create(config.jwksUrl()).toURL(), new DefaultResourceRetriever(3000, 3000, 64 * 1024))
                .retrying(true)
                .build();
        } catch (MalformedURLException | IllegalArgumentException e) {
            throw new AuthFIException("Invalid JWKS URL: " + config.jwksUrl(), e);
        }
    }

    private static AuthFIException refuse(String code) {
        return new AuthFIException("Token verification failed: " + code, 401, code);
    }

    /** Verify a JWT string and return parsed claims. */
    public AuthFIClaims verify(String token) {
        if (token == null || token.isBlank()) {
            throw refuse("token_missing");
        }
        if (token.length() > MAX_TOKEN_CHARS || token.chars().filter(c -> c == '.').count() != 2) {
            throw refuse("token_malformed");
        }
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw refuse("token_malformed");
        }
        JWSHeader header = jwt.getHeader();

        String typ = header.getType() == null ? null : header.getType().getType();
        if (typ == null || !(typ.equalsIgnoreCase("at+jwt") || typ.equalsIgnoreCase("application/at+jwt"))) {
            throw refuse("token_not_access_token");
        }
        if (!ALGORITHMS.contains(header.getAlgorithm().getName())) {
            throw refuse("token_signature_invalid");
        }
        if (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty()) {
            throw refuse("token_claims_invalid");
        }
        if (header.getKeyID() == null || header.getKeyID().isBlank()) {
            throw refuse("token_key_unknown");
        }

        verifySignature(jwt, header);

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw refuse("token_malformed");
        }
        checkClaims(claims);
        return AuthFIClaims.from(claims);
    }

    private void verifySignature(SignedJWT jwt, JWSHeader header) {
        List<JWK> candidates;
        try {
            candidates = keys.get(new JWKSelector(new JWKMatcher.Builder().keyID(header.getKeyID()).build()), null);
        } catch (Exception e) {
            throw new AuthFIException("The signing keys could not be fetched", 503, "token_key_unknown");
        }
        if (candidates == null || candidates.isEmpty()) {
            throw refuse("token_key_unknown");
        }
        JWK key = candidates.get(0);
        // A key that declares an algorithm signs with that one only; the token's header never overrides it.
        JWSAlgorithm alg = header.getAlgorithm();
        if (key.getAlgorithm() != null && !key.getAlgorithm().getName().equals(alg.getName())) {
            throw refuse("token_signature_invalid");
        }
        try {
            boolean ok = alg.equals(JWSAlgorithm.EdDSA) && key instanceof OctetKeyPair okp
                ? verifyEd25519(jwt, okp)
                : jwt.verify(verifierFor(alg, key));
            if (!ok) {
                throw refuse("token_signature_invalid");
            }
        } catch (JOSEException | GeneralSecurityException e) {
            // The key's type does not suit the algorithm, or the key is unusable.
            throw refuse("token_signature_invalid");
        }
    }

    /** SPKI prefix of an Ed25519 public key; the 32-byte key follows. */
    private static final byte[] ED25519_SPKI = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

    /**
     * Ed25519 is checked with the JDK's own provider (Java 15 and later), so the SDK needs no extra
     * crypto library on the path that decides whether a token is genuine.
     */
    private static boolean verifyEd25519(SignedJWT jwt, OctetKeyPair okp) throws GeneralSecurityException {
        if (!Curve.Ed25519.equals(okp.getCurve())) {
            return false;
        }
        byte[] x = okp.getDecodedX();
        if (x.length != 32) {
            return false;
        }
        byte[] spki = new byte[ED25519_SPKI.length + 32];
        System.arraycopy(ED25519_SPKI, 0, spki, 0, ED25519_SPKI.length);
        System.arraycopy(x, 0, spki, ED25519_SPKI.length, 32);
        Signature sig = Signature.getInstance("Ed25519");
        sig.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki)));
        sig.update(jwt.getSigningInput());
        return sig.verify(jwt.getSignature().decode());
    }

    private static JWSVerifier verifierFor(JWSAlgorithm alg, JWK key) throws JOSEException {
        if (alg.equals(JWSAlgorithm.ES256) && key instanceof ECKey ec) {
            return new ECDSAVerifier(ec.toPublicJWK());
        }
        if ((alg.equals(JWSAlgorithm.RS256) || alg.equals(JWSAlgorithm.PS256)) && key instanceof RSAKey rsa) {
            return new RSASSAVerifier(rsa.toPublicJWK());
        }
        throw new JOSEException("key type does not suit " + alg.getName());
    }

    private void checkClaims(JWTClaimsSet c) {
        if (!config.issuer().equals(c.getIssuer())) {
            throw refuse("token_issuer_not_accepted");
        }
        Date exp = c.getExpirationTime();
        if (exp == null) {
            throw refuse("token_claims_invalid");
        }
        long now = System.currentTimeMillis();
        if (exp.getTime() + leewayMillis < now) {
            throw refuse("token_expired");
        }
        if (c.getNotBeforeTime() != null && c.getNotBeforeTime().getTime() - leewayMillis > now) {
            throw refuse("token_claims_invalid");
        }
        if (c.getIssueTime() != null && c.getIssueTime().getTime() - leewayMillis > now) {
            throw refuse("token_claims_invalid");
        }
        if (c.getSubject() == null || c.getSubject().isBlank()) {
            throw refuse("token_claims_invalid");
        }
        List<String> aud = c.getAudience();
        if (aud == null || aud.stream().noneMatch(audiences::contains)) {
            throw refuse("token_audience_mismatch");
        }
        Object tenant = c.getClaim("tenant_id");
        if (!(tenant instanceof String t) || t.isBlank()) {
            throw refuse("token_no_tenant");
        }
        if (expectedTenantId != null && !expectedTenantId.equals(t)) {
            throw refuse("token_tenant_not_issuers");
        }
        if (c.getClaim("cnf") != null || c.getClaim("authfi_mandate") != null) {
            throw refuse("token_dpop_proof_required");
        }
        if (c.getClaim("act") instanceof Map<?, ?> act && act.containsKey("act")) {
            throw refuse("token_act_chain_unsupported");
        }
    }

    /** Verify from Authorization header value (Bearer xxx). */
    public AuthFIClaims verifyHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw refuse("token_missing");
        }
        return verify(authorizationHeader.substring(7).trim());
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
