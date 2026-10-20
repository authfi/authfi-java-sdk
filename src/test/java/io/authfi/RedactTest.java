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
}
