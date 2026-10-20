package io.authfi;

import com.sun.net.httpserver.HttpServer;
import io.authfi.agent.AgentCredentials;
import io.authfi.spring.AuthFIProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * No secret may appear in any output the SDK produces: toString, formatted strings, exception
 * messages, causes and stack traces. The record's generated toString once printed the API key, both
 * secrets and the agent's private key, so a single logged config leaked every credential.
 */
class SecretLeakTest {

    static final String API_KEY = "sk_" + "live_LEAKMARKERAPIKEY1234567890";
    static final String CLIENT_SECRET = "FIS-LEAKMARKERCLIENTSECRET9876";
    static final String AGENT_SECRET = "ags_LEAKMARKERAGENTSECRET5555";
    static final String PRIVATE_KEY =
        "-----BEGIN PRIVATE KEY-----\nLEAKMARKERPRIVATEKEYBODYAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n";
    static final List<String> MARKERS = List.of(
        "LEAKMARKERAPIKEY", "LEAKMARKERCLIENTSECRET", "LEAKMARKERAGENTSECRET", "LEAKMARKERPRIVATEKEY");

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    static void assertNoSecret(String where, String text) {
        for (String m : MARKERS) {
            assertFalse(text != null && text.contains(m), where + " leaked " + m + ": " + text);
        }
    }

    static String everything(Throwable t) {
        StringBuilder all = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            all.append(c).append('\n');
        }
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        return all.append(sw).toString();
    }

    private static AuthFIConfig fullConfig(String baseUrl) {
        return new AuthFIConfig("acme", API_KEY, "FIC-1", CLIENT_SECRET, "agt_1", AGENT_SECRET,
            PRIVATE_KEY, "key-1", baseUrl, AuthFIConfig.AuthMode.API_KEY);
    }

    @Test
    void configPrintsNoSecret() {
        AuthFIConfig c = fullConfig("https://api.authfi.io");
        assertNoSecret("toString", c.toString());
        assertNoSecret("String.valueOf", String.valueOf(c));
        assertNoSecret("format", String.format("%s | %s", c, List.of(c)));
        assertTrue(c.toString().contains("acme"), "identifiers still print");
        assertTrue(c.toString().contains("agt_1"));
    }

    @Test
    void propertiesAndRegistrationResultPrintNoSecret() {
        var props = new AuthFIProperties();
        props.setApiKey(API_KEY);
        props.setClientSecret(CLIENT_SECRET);
        props.getAgent().setSecret(AGENT_SECRET);
        assertNoSecret("AuthFIProperties", props.toString());

        var creds = new AgentCredentials("agt_1", AGENT_SECRET, "autonomous", "usr_1", 1L, null);
        assertNoSecret("AgentCredentials", creds.toString());
        assertTrue(creds.toString().contains("agt_1"));
        assertEquals(AGENT_SECRET, creds.clientSecret(), "the accessor still hands the secret to the caller");
    }

    @Test
    void anErrorBodyThatEchoesSecretsIsMaskedInTheException() throws Exception {
        // A server that reflects the request (headers and form body) in its 401 answer.
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String echo = "{\"error\":\"invalid_client\",\"received_key\":\"" + ex.getRequestHeaders().getFirst("X-API-Key")
                + "\",\"form\":\"" + body + "\",\"pem\":\"" + PRIVATE_KEY.replace("\n", "\\n")
                + "\",\"agent\":\"" + AGENT_SECRET + "\"}";
            byte[] b = echo.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(401, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();

        // Management call with the API key.
        var apiKey = new HttpTransport(fullConfig(base));
        var e1 = assertThrows(AuthFIException.class, () -> apiKey.get("/users"));
        assertEquals(401, e1.getStatus());
        assertNoSecret("API error", everything(e1));

        // Client-credentials token request: the client secret is in the form body.
        var cc = new HttpTransport(new AuthFIConfig("acme", null, "FIC-1", CLIENT_SECRET, null, null, null, null,
            base, AuthFIConfig.AuthMode.CLIENT_CREDENTIALS));
        var e2 = assertThrows(AuthFIException.class, cc::clientCredentialsToken);
        assertNoSecret("token request", everything(e2));
        assertTrue(e2.getMessage().contains("invalid_client"), "the useful part of the error survives");

        // Token exchange.
        var e3 = assertThrows(AuthFIException.class, () -> cc.tokenExchange("subject-token"));
        assertNoSecret("token exchange", everything(e3));
    }

    @Test
    void exceptionsMaskSecretShapedTextWhoeverBuildsThem() {
        String jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c3JfMSJ9.c2lnbmF0dXJlYnl0ZXM";
        var e = new AuthFIException("failed with " + jwt + " and client_secret=" + CLIENT_SECRET + " and " + PRIVATE_KEY, 500);
        assertFalse(e.getMessage().contains(jwt));
        assertNoSecret("exception", e.getMessage());
        var e2 = new AuthFIException("ags " + AGENT_SECRET + " " + API_KEY, new RuntimeException("x"));
        assertNoSecret("exception with cause", e2.getMessage());
    }
}
