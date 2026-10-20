package io.authfi.auth;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.authfi.AuthFIConfig;
import io.authfi.AuthFIException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TokenVerifierTest {

    static final String AUD = "api_orders";

    static AuthFIConfig testConfig() {
        return new AuthFIConfig("test", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
    }

    static String iss() {
        return testConfig().issuer();
    }

    /** A key of each kind the issuer publishes. */
    record Keys(RSAKey rsa, ECKey ec, OctetKeyPair okp) {
        static Keys generate() throws Exception {
            return new Keys(
                new RSAKeyGenerator(2048).keyID("rsa1").generate(),
                new ECKeyGenerator(Curve.P_256).keyID("ec1").generate(),
                new OctetKeyPairGenerator(Curve.Ed25519).keyID("ed1").generate());
        }

        JWKSet publicSet() {
            return new JWKSet(List.of(rsa.toPublicJWK(), ec.toPublicJWK(), okp.toPublicJWK()));
        }
    }

    static JWTClaimsSet.Builder goodClaims() {
        return new JWTClaimsSet.Builder()
            .subject("usr_1")
            .issuer(iss())
            .audience(AUD)
            .claim("tenant_id", "t-1")
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 60_000));
    }

    static String sign(JWK key, JWSAlgorithm alg, String typ, JWTClaimsSet claims) throws Exception {
        JWSHeader.Builder h = new JWSHeader.Builder(alg).keyID(key.getKeyID());
        if (typ != null) h.type(new JOSEObjectType(typ));
        SignedJWT jwt = new SignedJWT(h.build(), claims);
        if (key instanceof RSAKey k) jwt.sign(new RSASSASigner(k));
        else if (key instanceof ECKey k) jwt.sign(new ECDSASigner(k));
        else jwt.sign(new Ed25519Signer((OctetKeyPair) key));
        return jwt.serialize();
    }

    static TokenVerifier verifierFor(Keys keys) {
        return TokenVerifier.builder(testConfig()).audience(AUD)
            .keys(new ImmutableJWKSet<>(keys.publicSet())).build();
    }

    static void assertRefused(String code, TokenVerifier v, String token) {
        var ex = assertThrows(AuthFIException.class, () -> v.verify(token), code);
        assertEquals(401, ex.getStatus());
        assertEquals(code, ex.getCode());
    }

    @Test
    void verifiesEveryAlgorithmTheIssuerPublishes() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        assertEquals("usr_1", v.verify(sign(k.rsa, JWSAlgorithm.RS256, "at+jwt", goodClaims().build())).sub());
        assertEquals("usr_1", v.verify(sign(k.ec, JWSAlgorithm.ES256, "at+jwt", goodClaims().build())).sub());
        assertEquals("usr_1", v.verify(sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt", goodClaims().build())).sub());
        assertEquals("usr_1", v.verify(sign(k.rsa, JWSAlgorithm.PS256, "application/at+jwt", goodClaims().build())).sub());
    }

    @Test
    void refusesAnIdTokenOfferedAsAnAccessToken() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        for (String typ : new String[]{"JWT", null, "txn_token+jwt", "secevent+jwt"}) {
            assertRefused("token_not_access_token", v, sign(k.rsa, JWSAlgorithm.RS256, typ, goodClaims().build()));
            assertRefused("token_not_access_token", v, sign(k.okp, JWSAlgorithm.EdDSA, typ, goodClaims().build()));
        }
    }

    @Test
    void refusesWrongIssuerAudienceAndExpiry() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        assertRefused("token_issuer_not_accepted", v,
            sign(k.rsa, JWSAlgorithm.RS256, "at+jwt", goodClaims().issuer("https://evil.example").build()));
        assertRefused("token_audience_mismatch", v,
            sign(k.rsa, JWSAlgorithm.RS256, "at+jwt", goodClaims().audience("api_other").build()));
        assertRefused("token_audience_mismatch", v,
            sign(k.rsa, JWSAlgorithm.RS256, "at+jwt", goodClaims().audience((String) null).build()));
        assertRefused("token_expired", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().expirationTime(new Date(System.currentTimeMillis() - 120_000)).build()));
        assertRefused("token_claims_invalid", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().expirationTime(null).build()));
        assertRefused("token_claims_invalid", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().notBeforeTime(new Date(System.currentTimeMillis() + 600_000)).build()));
        assertRefused("token_claims_invalid", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().subject(null).build()));
        assertRefused("token_no_tenant", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().claim("tenant_id", null).build()));
    }

    @Test
    void acceptsAnyListedAudienceInAMultiValuedClaim() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        assertEquals("usr_1", v.verify(sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().audience(List.of("api_other", AUD)).build())).sub());
    }

    @Test
    void refusesAnUnknownKidAndAForgedSignature() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        OctetKeyPair stranger = new OctetKeyPairGenerator(Curve.Ed25519).keyID("nope").generate();
        assertRefused("token_key_unknown", v, sign(stranger, JWSAlgorithm.EdDSA, "at+jwt", goodClaims().build()));
        // Signed by a stranger but claiming the issuer's kid.
        OctetKeyPair forger = new OctetKeyPairGenerator(Curve.Ed25519).keyID("ed1").generate();
        assertRefused("token_signature_invalid", v, sign(forger, JWSAlgorithm.EdDSA, "at+jwt", goodClaims().build()));
        // Header says RS256 but names the Ed25519 key.
        RSAKey rsaWithEdKid = new RSAKeyGenerator(2048).keyID("ed1").generate();
        assertRefused("token_signature_invalid", v, sign(rsaWithEdKid, JWSAlgorithm.RS256, "at+jwt", goodClaims().build()));
    }

    @Test
    void refusesHeaderAlgorithmThatDisagreesWithTheKey() throws Exception {
        Keys k = Keys.generate();
        var withDeclaredAlg = new RSAKeyGenerator(2048).keyID("rsa1").algorithm(JWSAlgorithm.RS256).generate();
        var v = TokenVerifier.builder(testConfig()).audience(AUD)
            .keys(new ImmutableJWKSet<>(new JWKSet(withDeclaredAlg.toPublicJWK()))).build();
        // The key is published for RS256 only; PS256 over the same key must not verify.
        assertRefused("token_signature_invalid", v, sign(withDeclaredAlg, JWSAlgorithm.PS256, "at+jwt", goodClaims().build()));
        assertEquals("usr_1", v.verify(sign(withDeclaredAlg, JWSAlgorithm.RS256, "at+jwt", goodClaims().build())).sub());
    }

    @Test
    void refusesNoneAndHmacAndJwe() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        var enc = Base64.getUrlEncoder().withoutPadding();
        String claims = enc.encodeToString(goodClaims().build().toString().getBytes());
        String none = enc.encodeToString("{\"alg\":\"none\",\"typ\":\"at+jwt\",\"kid\":\"rsa1\"}".getBytes())
            + "." + claims + ".";
        assertThrows(AuthFIException.class, () -> v.verify(none));

        SignedJWT hs = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256)
            .type(new JOSEObjectType("at+jwt")).keyID("rsa1").build(), goodClaims().build());
        hs.sign(new MACSigner(new byte[32]));
        assertRefused("token_signature_invalid", v, hs.serialize());

        assertRefused("token_malformed", v, "a.b.c.d.e");
        assertRefused("token_malformed", v, "x".repeat(17 * 1024));
        assertRefused("token_missing", v, "");
    }

    @Test
    void refusesSenderConstrainedAndChainedTokens() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        assertRefused("token_dpop_proof_required", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().claim("cnf", Map.of("jkt", "x")).build()));
        assertRefused("token_dpop_proof_required", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().claim("authfi_mandate", "m").build()));
        assertRefused("token_act_chain_unsupported", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().claim("act", Map.of("sub", "a", "act", Map.of("sub", "b"))).build()));
        // One act is the ordinary agent-for-a-person token.
        var claims = v.verify(sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().claim("act", Map.of("sub", "agt_1")).build()));
        assertEquals("agt_1", claims.actor());
        assertEquals(List.of(AUD), claims.audience());
    }

    @Test
    void pinsTheTenantWhenAsked() throws Exception {
        Keys k = Keys.generate();
        var v = TokenVerifier.builder(testConfig()).audience(AUD).expectedTenantId("t-2")
            .keys(new ImmutableJWKSet<>(k.publicSet())).build();
        assertRefused("token_tenant_not_issuers", v, sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt", goodClaims().build()));
    }

    @Test
    void leewayAcceptsASlightlyExpiredToken() throws Exception {
        Keys k = Keys.generate();
        String token = sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().expirationTime(new Date(System.currentTimeMillis() - 30_000)).build());
        assertEquals("usr_1", verifierFor(k).verify(token).sub());
        var strict = TokenVerifier.builder(testConfig()).audience(AUD).leeway(Duration.ZERO)
            .keys(new ImmutableJWKSet<>(k.publicSet())).build();
        assertRefused("token_expired", strict, token);
    }

    @Test
    void aVerifierWithoutAnAudienceCannotBeBuilt() {
        assertThrows(IllegalArgumentException.class, () -> new TokenVerifier(testConfig()));
        assertThrows(IllegalArgumentException.class, () -> TokenVerifier.builder(testConfig()).build());
    }

    @Test
    void refusesAuthFiOwnAudiences() {
        for (String own : new String[]{iss(), iss() + "/mcp", "https://api.authfi.io", "https://api.authfi.io/x",
            "authfi-console", "authfi-workspace"}) {
            assertThrows(IllegalArgumentException.class, () -> new TokenVerifier(testConfig(), own), own);
        }
    }

    @Test
    void headerHelpers() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        assertRefused("token_missing", v, null);
        assertEquals(401, assertThrows(AuthFIException.class, () -> v.verifyHeader(null)).getStatus());
        assertThrows(AuthFIException.class, () -> v.verifyHeader("Basic abc123"));
        String t = sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt", goodClaims().build());
        assertEquals("usr_1", v.verifyHeader("Bearer " + t).sub());
    }

    @Test
    void requirePermissionsThrowsOnMissing() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        var claims = v.verify(sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().claim("permissions", List.of("read:users")).build()));
        assertDoesNotThrow(() -> v.requirePermissions(claims, "read:users"));
        assertEquals(403, assertThrows(AuthFIException.class, () -> v.requirePermissions(claims, "delete:users")).getStatus());
    }

    @Test
    void requireRoleThrowsOnMissing() throws Exception {
        Keys k = Keys.generate();
        var v = verifierFor(k);
        var claims = v.verify(sign(k.okp, JWSAlgorithm.EdDSA, "at+jwt",
            goodClaims().claim("roles", List.of("editor")).build()));
        assertDoesNotThrow(() -> v.requireRole(claims, "editor"));
        assertEquals(403, assertThrows(AuthFIException.class, () -> v.requireRole(claims, "admin")).getStatus());
    }
}
