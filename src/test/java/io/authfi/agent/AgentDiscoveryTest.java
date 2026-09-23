package io.authfi.agent;

import com.sun.net.httpserver.HttpServer;
import io.authfi.AuthFIException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Discovery is how this SDK stopped guessing where the agent surface lives.
 *
 * 0.3.0 constructed the token URL from tenant and version and it resolved to a 404 — the platform
 * serves the agent endpoints under a prefix no concatenation would arrive at. These tests exercise
 * the real fetch path against a local server rather than a parsed string, because the failure being
 * guarded against was a URL that looked plausible and did not exist.
 */
class AgentDiscoveryTest {

    private HttpServer server;

    private String serve(int status, String body) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(AgentDiscovery.PATH, ex -> {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    /** The shape production actually serves, trimmed to what this SDK reads. */
    private static final String REAL = """
        {"issuer":"https://platform.authfi.io",
         "algorithms":["EdDSA"],
         "grant_types_supported":["client_credentials","urn:openid:params:grant-type:ciba"],
         "token_endpoint_auth_methods_supported":["private_key_jwt"],
         "backchannel_authentication_endpoint":"https://platform.authfi.io/apis/regional/v1/ai/auth/backchannel-authorize",
         "endpoints":{"token":"https://platform.authfi.io/apis/regional/v1/ai/auth/token",
                      "register":"https://platform.authfi.io/apis/regional/v1/ai/auth/register"}}
        """;

    @Test
    void readsTheTokenEndpointThePlatformAdvertises() throws Exception {
        var d = AgentDiscovery.fetch(HttpClient.newHttpClient(), serve(200, REAL));
        // The whole point: this is NOT a path the SDK could have built.
        assertEquals("https://platform.authfi.io/apis/regional/v1/ai/auth/token", d.tokenEndpoint());
        assertTrue(d.backchannelEndpoint().endsWith("/backchannel-authorize"));
        assertTrue(d.grantTypesSupported().contains("client_credentials"));
    }

    @Test
    void refusesADeploymentThatDoesNotOfferPrivateKeyJwt() throws Exception {
        String doc = """
            {"endpoints":{"token":"https://x.example/token"},
             "token_endpoint_auth_methods_supported":["client_secret_post"]}
            """;
        var e = assertThrows(AuthFIException.class,
            () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), serve(200, doc)));
        // A server that does not offer the method we implement is a configuration answer, not a
        // runtime error to retry — and the message has to say which methods it DID offer.
        assertTrue(e.getMessage().contains("private_key_jwt"), e.getMessage());
        assertTrue(e.getMessage().contains("client_secret_post"), e.getMessage());
    }

    @Test
    void acceptsTheTopLevelTokenEndpointSpelling() throws Exception {
        String doc = """
            {"token_endpoint":"https://x.example/t","token_endpoint_auth_methods_supported":["private_key_jwt"]}
            """;
        assertEquals("https://x.example/t",
            AgentDiscovery.fetch(HttpClient.newHttpClient(), serve(200, doc)).tokenEndpoint());
    }

    @Test
    void aDocumentWithNoTokenEndpointIsRefusedRatherThanReturnedEmpty() throws Exception {
        var e = assertThrows(AuthFIException.class,
            () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), serve(200, "{\"issuer\":\"x\"}")));
        assertTrue(e.getMessage().contains("no token endpoint"), e.getMessage());
    }

    @Test
    void anHttpErrorNamesTheUrlAndTheStatus() throws Exception {
        String base = serve(404, "nope");
        var e = assertThrows(AuthFIException.class,
            () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), base));
        // "discovery failed" on its own sends people to the wrong place.
        assertTrue(e.getMessage().contains(AgentDiscovery.PATH), e.getMessage());
        assertTrue(e.getMessage().contains("404"), e.getMessage());
    }

    @Test
    void anUnreachableIssuerFailsWithTheUrlNamed() {
        // Port 1 on loopback: nothing listens, and it fails fast rather than hanging the suite.
        var e = assertThrows(AuthFIException.class,
            () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), "http://127.0.0.1:1"));
        assertTrue(e.getMessage().contains("could not be read"), e.getMessage());
    }
}
