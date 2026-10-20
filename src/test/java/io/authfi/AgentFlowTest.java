package io.authfi;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;
import io.authfi.agent.AgentAuthClient;
import io.authfi.agent.AgentDiscovery;
import io.authfi.agent.Approval;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The agent mints at the authorization server's token endpoint and asks for approvals at the
 * advertised endpoint, signing with its key. A key-registered agent has no client secret, so any
 * request that carries one is wrong for it.
 */
class AgentFlowTest {

    private HttpServer server;
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private final List<String> auth = new CopyOnWriteArrayList<>();
    private String base;

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    private void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        // Authorization-server metadata: the one token endpoint. The agent document still advertises
        // the deprecated token route, which must NOT be used.
        reply("/.well-known/oauth-authorization-server", 200, "{\"issuer\":\"" + base + "\",\"token_endpoint\":\"" + base + "/oauth/token\","
            + "\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\"],"
            + "\"backchannel_authentication_endpoint\":\"" + base + "/ciba\"}");
        reply("/.well-known/agent-configuration", 200, "{\"endpoints\":{"
            + "\"token\":\"" + base + "/deprecated/token\","
            + "\"request_approval\":\"" + base + "/approvals\","
            + "\"approval\":\"" + base + "/approvals/{id}\"}}");
        server.createContext("/oauth/token", ex -> {
            requests.add("POST /oauth/token " + new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            answer(ex, 200, "{\"access_token\":\"tok-1\",\"expires_in\":3600,\"capabilities\":[\"send_email\"]}");
        });
        server.createContext("/deprecated/token", ex -> {
            requests.add("POST /deprecated/token");
            answer(ex, 404, "{}");
        });
        server.createContext("/approvals", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            auth.add(String.valueOf(ex.getRequestHeaders().getFirst("Authorization")));
            if (ex.getRequestMethod().equals("POST")) {
                requests.add("POST /approvals " + body);
                answer(ex, 202, "{\"data\":{\"approval_id\":\"ap-1\",\"status\":\"pending\",\"expires_at\":\"2026-10-21T00:00:00Z\"}}");
            } else {
                requests.add(ex.getRequestMethod() + " " + ex.getRequestURI().getPath());
                String id = ex.getRequestURI().getPath().substring("/approvals/".length());
                String status = id.startsWith("ap-") && id.length() > 3 ? id.substring(3) : "approved";
                answer(ex, 200, "{\"data\":{\"approval_id\":\"" + id + "\",\"status\":\"" + status + "\",\"approver_user_id\":\"usr_9\","
                    + "\"expires_at\":\"2026-10-21T00:00:00Z\",\"resolved_at\":\"2026-10-20T12:00:00Z\"}}");
            }
        });
        server.start();
    }

    private void reply(String path, int status, String body) {
        server.createContext(path, ex -> answer(ex, status, body));
    }

    private static void answer(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private static KeyPair keys;

    private static String pem() throws Exception {
        keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        return "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(keys.getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----\n";
    }

    private HttpTransport transport() throws Exception {
        var config = new AuthFIConfig("acme", null, null, null, "agt_1", null, pem(), "key-1", base,
            AuthFIConfig.AuthMode.AGENT_CREDENTIALS);
        var http = new HttpTransport(config);
        http.useDiscovery(AgentDiscovery.fetch(HttpClient.newHttpClient(), base));
        return http;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> assertion(String jws, String aud) throws Exception {
        String[] p = jws.split("\\.");
        Signature v = Signature.getInstance("Ed25519");
        v.initVerify(keys.getPublic());
        v.update((p[0] + "." + p[1]).getBytes(StandardCharsets.UTF_8));
        assertTrue(v.verify(Base64.getUrlDecoder().decode(p[2])), "signed by the agent's key");
        Map<String, Object> claims = new Gson().fromJson(
            new String(Base64.getUrlDecoder().decode(p[1]), StandardCharsets.UTF_8), Map.class);
        assertEquals(aud, claims.get("aud"));
        return claims;
    }

    @Test
    void discoveryPrefersTheAuthorizationServerTokenEndpoint() throws Exception {
        start();
        var d = AgentDiscovery.fetch(HttpClient.newHttpClient(), base);
        assertEquals(base + "/oauth/token", d.tokenEndpoint());
        assertEquals(base + "/ciba", d.backchannelEndpoint());
        assertEquals(base + "/approvals", d.requestApprovalEndpoint());
        assertEquals(base + "/approvals/{id}", d.approvalEndpoint());
    }

    @Test
    void theAgentMintsAtTheAuthorizationServerAndSignsForThatEndpoint() throws Exception {
        start();
        var http = transport();
        assertEquals("tok-1", http.agentToken());
        assertEquals(List.of("send_email"), List.copyOf(http.agentCapabilities()));
        assertEquals(1, requests.size());
        assertTrue(requests.get(0).startsWith("POST /oauth/token "), requests.get(0));
        String form = requests.get(0);
        assertFalse(form.contains("client_secret"));
        String jws = java.net.URLDecoder.decode(form.replaceAll(".*client_assertion=([^&]+).*", "$1"), StandardCharsets.UTF_8);
        assertion(jws, base + "/oauth/token");
    }

    @Test
    void anApprovalRequestIsSignedForTheIssuerAndCarriesNoSecret() throws Exception {
        start();
        var http = transport();
        var client = new AgentAuthClient(configOf(http), http);
        var req = client.requestApproval("send_email", Map.of("to", "boss"));
        assertEquals("ap-1", req.approvalId());
        assertEquals("pending", req.status());
        assertEquals(java.time.Instant.parse("2026-10-21T00:00:00Z").getEpochSecond(), req.expiresAtEpochSec());

        String posted = requests.stream().filter(r -> r.startsWith("POST /approvals ")).findFirst().orElseThrow();
        String json = posted.substring("POST /approvals ".length());
        assertFalse(json.contains("client_secret"), json);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = new Gson().fromJson(json, Map.class);
        assertEquals("agt_1", body.get("agent_id"));
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", body.get("client_assertion_type"));
        assertion((String) body.get("client_assertion"), base);
    }

    @Test
    void approvalStatusIsReadAtTheAdvertisedEndpointWithTheAgentToken() throws Exception {
        start();
        var http = transport();
        var client = new AgentAuthClient(configOf(http), http);
        Approval a = client.checkApproval("ap-approved");
        assertInstanceOf(Approval.Approved.class, a);
        assertTrue(requests.contains("GET /approvals/ap-approved"), requests.toString());
        assertEquals("Bearer tok-1", auth.get(auth.size() - 1));
    }

    private AuthFIConfig configOf(HttpTransport http) throws Exception {
        var f = HttpTransport.class.getDeclaredField("config");
        f.setAccessible(true);
        return (AuthFIConfig) f.get(http);
    }

    private void serve(int asStatus, String asBody, int agentStatus, String agentBody) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/.well-known/oauth-authorization-server", ex -> answer(ex, asStatus, asBody.replace("BASE", base)));
        server.createContext("/.well-known/agent-configuration", ex -> answer(ex, agentStatus, agentBody.replace("BASE", base)));
        server.start();
    }

    @Test
    void aTransientFailureOfEitherDocumentIsNotCachedAsAbsence() throws Exception {
        serve(200, "{\"token_endpoint\":\"BASE/oauth/token\"}", 503, "{}");
        var e = assertThrows(AuthFIException.class, () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), base));
        assertEquals(503, e.getStatus());
        server.stop(0);
        serve(503, "{}", 200, "{\"endpoints\":{\"token\":\"BASE/deprecated\"}}");
        var e2 = assertThrows(AuthFIException.class, () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), base));
        assertEquals(503, e2.getStatus());
    }

    @Test
    void aDeploymentThatServesOnlyTheAuthorizationServerDocumentStillMints() throws Exception {
        serve(200, "{\"token_endpoint\":\"BASE/oauth/token\"}", 404, "{}");
        var d = AgentDiscovery.fetch(HttpClient.newHttpClient(), base);
        assertEquals(base + "/oauth/token", d.tokenEndpoint());
        assertNull(d.requestApprovalEndpoint());
        var http = new HttpTransport(new AuthFIConfig("acme", null, null, null, "agt_1", null, pem(), "key-1", base,
            AuthFIConfig.AuthMode.AGENT_CREDENTIALS));
        http.useDiscovery(d);
        assertEquals(501, assertThrows(AuthFIException.class, () -> http.requestApproval("x", Map.of())).getStatus());
        assertEquals(501, assertThrows(AuthFIException.class, () -> http.approvalStatus("ap-1")).getStatus());
    }

    @Test
    void theAgentDocumentIsTheFallbackWhenTheAuthorizationServerAdvertisesNoTokenEndpoint() throws Exception {
        serve(200, "{\"token_endpoint\":\"  \"}", 200, "{\"endpoints\":{\"token\":\"BASE/legacy\"}}");
        assertEquals(base + "/legacy", AgentDiscovery.fetch(HttpClient.newHttpClient(), base).tokenEndpoint());
        server.stop(0);
        serve(404, "{}", 404, "{}");
        assertEquals(404, assertThrows(AuthFIException.class, () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), base)).getStatus());
        server.stop(0);
        serve(200, "{}", 200, "{\"endpoints\":{}}");
        assertEquals(502, assertThrows(AuthFIException.class, () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), base)).getStatus());
    }

    @Test
    void credentialsAreNeverSentToANonHttpsEndpoint() throws Exception {
        for (String bad : new String[]{"http://evil.example/oauth/token", "ftp://evil.example/t", "not a url"}) {
            serve(200, "{\"token_endpoint\":\"" + bad + "\"}", 404, "{}");
            var e = assertThrows(AuthFIException.class, () -> AgentDiscovery.fetch(HttpClient.newHttpClient(), base), bad);
            assertEquals(502, e.getStatus());
            server.stop(0);
        }
        serve(200, "{\"token_endpoint\":\"https://platform-beta.authfi.io/oauth/token\"}", 404, "{}");
        assertEquals("https://platform-beta.authfi.io/oauth/token",
            AgentDiscovery.fetch(HttpClient.newHttpClient(), base).tokenEndpoint());
    }

    @Test
    void anAgentWithNoCredentialCannotRequestAnApproval() throws Exception {
        start();
        var http = new HttpTransport(new AuthFIConfig("acme", null, null, null, "agt_1", null, null, null, base,
            AuthFIConfig.AuthMode.AGENT_CREDENTIALS));
        http.useDiscovery(AgentDiscovery.fetch(HttpClient.newHttpClient(), base));
        assertEquals(401, assertThrows(AuthFIException.class, () -> http.requestApproval("x", Map.of())).getStatus());
        assertTrue(requests.stream().noneMatch(r -> r.startsWith("POST /approvals")), "nothing was sent");
    }

    @Test
    void theApprovalIdIsEncodedIntoTheStatusUrl() throws Exception {
        start();
        var http = transport();
        http.approvalStatus("a/b c");
        assertTrue(requests.contains("GET /approvals/a/b c") || requests.stream().anyMatch(r -> r.startsWith("GET /approvals/a")), requests.toString());
        assertTrue(requests.stream().noneMatch(r -> r.equals("GET /approvals/a/b")), "the slash did not split the path");
    }

    @Test
    void everyApprovalStatusOnTheWireIsReadTyped() throws Exception {
        start();
        var http = transport();
        var client = new AgentAuthClient(configOf(http), http);
        var approved = assertInstanceOf(Approval.Approved.class, client.checkApproval("ap-approved"));
        assertEquals("usr_9", approved.approverUserId());
        assertEquals(java.time.Instant.parse("2026-10-20T12:00:00Z").getEpochSecond(), approved.approvedAtEpochSec());
        assertInstanceOf(Approval.Denied.class, client.checkApproval("ap-denied"));
        assertInstanceOf(Approval.Expired.class, client.checkApproval("ap-expired"));
        assertInstanceOf(Approval.Pending.class, client.checkApproval("ap-pending"));
        assertEquals(502, assertThrows(AuthFIException.class, () -> client.checkApproval("ap-weird")).getStatus());
    }
}
