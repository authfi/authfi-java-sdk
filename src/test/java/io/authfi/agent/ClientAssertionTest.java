package io.authfi.agent;

import io.authfi.AuthFIConfig;
import io.authfi.AuthFIException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The assertion is the agent's whole credential, so these tests verify it the way the server
 * does — by checking the signature against the public half — rather than by asserting the shape
 * of a string. A JWS that merely looks right is exactly the failure worth catching.
 */
class ClientAssertionTest {

    private static final String AGENT = "agt_1234567890";
    private static final String AUD = "https://api.authfi.io/v1/acme/agents/token";
    private static final String KID = "key-1";

    private static KeyPair ed25519() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static String pkcs8Pem(KeyPair kp) {
        return "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(kp.getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----\n";
    }

    private static String seg(String jws, int i) {
        return new String(Base64.getUrlDecoder().decode(jws.split("\\.")[i]), StandardCharsets.UTF_8);
    }

    @Test
    void signatureVerifiesAgainstThePublicHalf() throws Exception {
        KeyPair kp = ed25519();
        String jws = ClientAssertion.build(AGENT, AUD, KID, pkcs8Pem(kp));

        String[] parts = jws.split("\\.");
        assertEquals(3, parts.length, "a compact JWS has three segments");

        Signature v = Signature.getInstance("Ed25519");
        v.initVerify(kp.getPublic());
        v.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        assertTrue(v.verify(Base64.getUrlDecoder().decode(parts[2])),
            "the server must be able to verify this with the registered public key");
    }

    @Test
    void headerNamesEdDSAAndTheRegisteredKid() {
        String jws = ClientAssertion.build(AGENT, AUD, KID, pkcs8Pem(keyPair()));
        String header = seg(jws, 0);
        assertTrue(header.contains("\"alg\":\"EdDSA\""), header);
        assertTrue(header.contains("\"typ\":\"JWT\""), header);
        // Without the kid the server cannot select which registered key to verify against.
        assertTrue(header.contains("\"kid\":\"key-1\""), header);
    }

    @Test
    void agentIsBothIssuerAndSubject() {
        String claims = seg(ClientAssertion.build(AGENT, AUD, KID, pkcs8Pem(keyPair())), 1);
        assertTrue(claims.contains("\"iss\":\"" + AGENT + "\""), claims);
        assertTrue(claims.contains("\"sub\":\"" + AGENT + "\""), claims);
    }

    @Test
    void audienceIsTheTokenEndpoint() {
        // Checked by the server: an assertion signed for one endpoint must not work at another.
        String claims = seg(ClientAssertion.build(AGENT, AUD, KID, pkcs8Pem(keyPair())), 1);
        assertTrue(claims.contains("\"aud\":\"" + AUD + "\""), claims);
    }

    @Test
    void eachAssertionCarriesAFreshJti() {
        String pem = pkcs8Pem(keyPair());
        String a = seg(ClientAssertion.build(AGENT, AUD, KID, pem), 1);
        String b = seg(ClientAssertion.build(AGENT, AUD, KID, pem), 1);
        // The replay id is what lets a server refuse a second use of the same credential. Reusing
        // one would make every assertion look like a replay of the last.
        assertNotEquals(jti(a), jti(b));
    }

    @Test
    void expiryIsShortAndInTheFuture() {
        String claims = seg(ClientAssertion.build(AGENT, AUD, KID, pkcs8Pem(keyPair())), 1);
        long iat = Long.parseLong(claims.replaceAll(".*\"iat\":(\\d+).*", "$1"));
        long exp = Long.parseLong(claims.replaceAll(".*\"exp\":(\\d+).*", "$1"));
        assertTrue(exp > iat, "exp must be after iat");
        // An assertion is a bearer credential for its lifetime, so the window stays small.
        assertTrue(exp - iat <= 600, "assertion lifetime should stay short, was " + (exp - iat) + "s");
    }

    @Test
    void segmentsAreBase64UrlWithoutPadding() {
        String jws = ClientAssertion.build(AGENT, AUD, KID, pkcs8Pem(keyPair()));
        for (String p : jws.split("\\.")) {
            assertFalse(p.contains("="), "no padding: " + p);
            assertFalse(p.contains("+") || p.contains("/"), "base64url alphabet only: " + p);
        }
    }

    @Test
    void aKeyThatIsNotPkcs8IsRefusedByName() {
        AuthFIException e = assertThrows(AuthFIException.class,
            () -> ClientAssertion.build(AGENT, AUD, KID,
                "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"));
        // The message has to say what was wrong and how to fix it — a JCA stack trace reads like
        // a platform fault and sends people to the wrong place.
        assertTrue(e.getMessage().contains("PKCS#8"), e.getMessage());
        assertTrue(e.getMessage().contains("openssl genpkey"), e.getMessage());
    }

    @Test
    void somethingThatIsNotPemAtAllSaysSo() {
        AuthFIException e = assertThrows(AuthFIException.class,
            () -> ClientAssertion.build(AGENT, AUD, KID, "hunter2"));
        assertTrue(e.getMessage().contains("not PEM"), e.getMessage());
    }

    @Test
    void missingInputsAreRefusedBeforeAnySigning() {
        String pem = pkcs8Pem(keyPair());
        assertThrows(AuthFIException.class, () -> ClientAssertion.build(null, AUD, KID, pem));
        assertThrows(AuthFIException.class, () -> ClientAssertion.build(AGENT, null, KID, pem));
        assertThrows(AuthFIException.class, () -> ClientAssertion.build(AGENT, AUD, "  ", pem));
        assertThrows(AuthFIException.class, () -> ClientAssertion.build(AGENT, AUD, KID, null));
    }

    @Test
    void configKnowsWhetherItCanSign() {
        var withKey = new AuthFIConfig("acme", null, null, null, AGENT, null,
            pkcs8Pem(keyPair()), KID, "https://api.authfi.io",
            AuthFIConfig.AuthMode.AGENT_CREDENTIALS);
        assertTrue(withKey.hasAgentKey());

        // A key without a kid is not usable: the server could not choose a verifying key.
        var noKid = new AuthFIConfig("acme", null, null, null, AGENT, null,
            pkcs8Pem(keyPair()), null, "https://api.authfi.io",
            AuthFIConfig.AuthMode.AGENT_CREDENTIALS);
        assertFalse(noKid.hasAgentKey());

        // The pre-key constructor still compiles and yields a secret-only config.
        var legacy = new AuthFIConfig("acme", null, null, null, AGENT, "shh",
            "https://api.authfi.io", AuthFIConfig.AuthMode.AGENT_CREDENTIALS);
        assertFalse(legacy.hasAgentKey());
        assertEquals("shh", legacy.agentSecret());
    }

    // === helpers ===

    private static String jti(String claims) {
        return claims.replaceAll(".*\"jti\":\"([^\"]+)\".*", "$1");
    }

    private static KeyPair keyPair() {
        try {
            return ed25519();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
