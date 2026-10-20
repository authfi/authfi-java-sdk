package io.authfi;

import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class RedactTest {

    private static void masked(String secret, String text) {
        String out = Redact.scrub(text);
        assertFalse(out.contains(secret), "leaked " + secret + " from: " + text + " -> " + out);
    }

    @Test
    void masksCredentialFieldsInEverySpelling() {
        String s = "opaqueSecretValue";
        masked(s, "client_secret=" + s);
        masked(s, "client_secret: " + s);
        masked(s, "{\"client_secret\":\"" + s + "\"}");
        masked(s, "{\\\"client_secret\\\":\\\"" + s + "\\\"}");
        masked(s, "client_secret%3D" + s);
        masked(s, "clientSecret=" + s);
        masked(s, "client-secret=" + s);
        masked(s, "refresh_token=" + s);
        masked(s, "refreshToken: " + s);
        masked(s, "api_key=" + s);
        masked(s, "X-API-Key: " + s);
        masked(s, "password=" + s);
        masked(s, "agent_secret=" + s);
        masked(s, "private_key=" + s);
        masked(s, "id_token=" + s);
        masked(s, "access_token=" + s);
        masked(s, "client_assertion=" + s);
        masked(s, "Authorization: Bearer " + s + "abc");
    }

    @Test
    void masksAQuotedValueThatContainsSpaces() {
        String out = Redact.scrub("client_secret=\"two words here\" and more");
        assertFalse(out.contains("words"), out);
        assertFalse(out.contains("here"), out);
        assertTrue(out.contains("and more"), "text outside the value survives: " + out);
    }

    @Test
    void masksSecretShapes() {
        masked("sk_live_abcdefgh12345", "key sk_live_abcdefgh12345 here");
        masked("sk_test_abcdefgh12345", "key sk_test_abcdefgh12345 here");
        masked("ags_abcdefgh12345", "x ags_abcdefgh12345");
        masked("FIS-abcdefgh12345", "x FIS-abcdefgh12345");
        masked("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c3JfMSJ9.c2ln", "t eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c3JfMSJ9.c2ln");
        masked("MIIEvQIBADANBgkq", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----");
        masked("MIIEvQIBADANBgkq", "-----BEGIN EC PRIVATE KEY-----\\nMIIEvQIBADANBgkq\\n-----END EC PRIVATE KEY-----");
    }

    @Test
    void leavesAHeaderOnlyHintAlone() {
        String hint = "must be PKCS#8 PEM form (-----BEGIN PRIVATE KEY-----), but it is an EC key";
        assertEquals(hint, Redact.scrub(hint));
    }

    @Test
    void masksLiteralSecretsPlainEscapedAndEncoded() {
        String secret = "pl\"ain+secret/with=chars&more";
        String json = secret.replace("\"", "\\\"");
        String form = URLEncoder.encode(secret, StandardCharsets.UTF_8);
        for (String text : new String[]{"x " + secret + " y", "x " + json + " y", "x " + form + " y"}) {
            String out = Redact.scrub(text, secret);
            assertFalse(out.contains("secret"), text + " -> " + out);
        }
    }

    @Test
    void literalSecretsOfFourCharactersAreMaskedButShorterOnesAreNot() {
        assertFalse(Redact.scrub("pw abcd pw", "abcd").contains("abcd"));
        assertEquals("pw abc pw", Redact.scrub("pw abc pw", "abc"));
    }

    @Test
    void nullAndEmptyPassThrough() {
        assertNull(Redact.scrub((String) null));
        assertEquals("", Redact.scrub(""));
        assertNull(Redact.scrub(null, "abcd"));
        assertEquals("plain text", Redact.scrub("plain text", (String) null));
    }

    private static String realPem(int bits) throws Exception {
        var g = java.security.KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        String body = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
            .encodeToString(g.generateKeyPair().getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }

    @Test
    void aRealSizedPrivateKeyIsMaskedWithoutOverflowingTheStack() throws Exception {
        for (int bits : new int[]{2048, 3072, 4096}) {
            String pem = realPem(bits);
            String out = assertDoesNotThrow(() -> Redact.scrub("failed with key " + pem + " end"));
            assertEquals("failed with key [redacted]\n end", out);
            assertDoesNotThrow(() -> new AuthFIException("x " + pem, 500));
        }
        String escaped = realPem(4096).replace("\n", "\n");
        String outEscaped = Redact.scrub("k " + escaped);
        assertTrue(outEscaped.startsWith("k [redacted]") && !outEscaped.contains("MII"), outEscaped);
    }

    @Test
    void hostileInputIsLinearAndDoesNotOverflow() {
        String[] hostile = {
            "-----BEGIN PRIVATE KEY-----" + "A".repeat(1_000_000),
            "-----BEGIN PRIVATE KEY-----" + " ".repeat(1_000_000),
            "-----BEGIN PRIVATE KEY-----" + "\n".repeat(500_000),
            "client_secret=".repeat(80_000),
            "secret".repeat(150_000)};
        for (String h : hostile) {
            long t = System.nanoTime();
            assertDoesNotThrow(() -> Redact.scrub(h));
            assertTrue((System.nanoTime() - t) / 1_000_000 < 5_000, "slow on hostile input");
        }
    }

    @Test
    void literalMaskingStillAppliesTheShapeMasking() {
        String out = Redact.scrub("pw hunter2hunter2 and eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c3JfMSJ9.c2ln", "hunter2hunter2");
        assertFalse(out.contains("hunter2"));
        assertFalse(out.contains("eyJhbGci"), out);
    }

    @Test
    void aSecretEchoedWithPercentTwentyOrLowerCaseHexIsMasked() {
        String secret = "a b/c+d";
        assertFalse(Redact.scrub("x a%20b%2Fc%2Bd y", secret).contains("%2"));
        assertFalse(Redact.scrub("x a+b%2fc%2bd y", secret).contains("%2"));
    }
}
