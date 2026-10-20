package io.authfi.agent;

import com.google.gson.Gson;
import io.authfi.AuthFIException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * The AuthFI Agent Profile discovery document — the only authority on where the endpoints are.
 *
 * <p><b>Why this exists, and it is not a nicety.</b> 0.3.0 built the agent token URL by hand, as
 * {@code baseUrl + "/" + tenant + "/v1/agents/token"}. That resolves to a <b>404</b>. The platform
 * serves the agent surface at {@code /apis/regional/v1/ai/auth/token}, and no amount of string
 * concatenation in an SDK was ever going to guess that. The crypto in 0.3.0 was right and the
 * address was wrong, which is the worst combination: everything looks correct until the first call.
 *
 * <p>So this SDK no longer guesses. It reads {@code /.well-known/agent-configuration} from the
 * project's issuer and uses the endpoints the platform itself advertises. That also means a
 * deployment can move its surface without every SDK in the field needing a release.
 *
 * <p>It refuses a deployment that does not advertise {@code private_key_jwt}, rather than trying
 * anyway and reporting whatever failure comes back. A server that does not offer the auth method
 * this SDK implements is a configuration answer, not a runtime error to be retried.
 *
 * <p>Fetched once per client and cached: the document changes at deployment time, and an agent that
 * re-read it on every token refresh would turn one dependency into a per-call one.
 */
public final class AgentDiscovery {

    /** RFC 8414-style well-known path, under the project's own issuer. */
    static final String PATH = "/.well-known/agent-configuration";

    /** RFC 8414 authorization-server metadata, where the one token endpoint is advertised. */
    static final String AS_PATH = "/.well-known/oauth-authorization-server";

    private final String tokenEndpoint;
    private final String backchannelEndpoint;
    private final List<String> authMethods;
    private final List<String> grantTypes;
    private final String requestApprovalEndpoint;
    private final String approvalEndpoint;

    private AgentDiscovery(String tokenEndpoint, String backchannelEndpoint,
                           List<String> authMethods, List<String> grantTypes,
                           String requestApprovalEndpoint, String approvalEndpoint) {
        this.requestApprovalEndpoint = requestApprovalEndpoint;
        this.approvalEndpoint = approvalEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.backchannelEndpoint = backchannelEndpoint;
        this.authMethods = authMethods;
        this.grantTypes = grantTypes;
    }

    /** Where to POST a client_credentials or CIBA token request. */
    public String tokenEndpoint() {
        return tokenEndpoint;
    }

    /** Where an agent asks a person to authorise it, or null when the deployment does not offer it. */
    public String backchannelEndpoint() {
        return backchannelEndpoint;
    }

    /** Where an agent asks for a human approval, or null when the deployment does not advertise it. */
    public String requestApprovalEndpoint() {
        return requestApprovalEndpoint;
    }

    /** The approval status URL with an {@code {id}} placeholder, or null when not advertised. */
    public String approvalEndpoint() {
        return approvalEndpoint;
    }

    public List<String> tokenEndpointAuthMethodsSupported() {
        return authMethods;
    }

    public List<String> grantTypesSupported() {
        return grantTypes;
    }

    /**
     * Read the endpoints the platform advertises for this issuer.
     *
     * <p>The token endpoint comes from the authorization-server metadata
     * ({@code /.well-known/oauth-authorization-server}): one token endpoint serves users, agents and
     * CIBA, and the agent-specific {@code endpoints.token} is deprecated. The approval endpoints
     * come from {@code /.well-known/agent-configuration}. When the authorization-server document is
     * not served, the agent document is the fallback for everything.
     *
     * @throws AuthFIException when neither can be read, or the deployment advertises no
     *         {@code private_key_jwt} or no token endpoint, each naming the issuer.
     */
    @SuppressWarnings("unchecked")
    public static AgentDiscovery fetch(HttpClient client, String issuer) {
        Map<String, Object> as = tryGet(client, issuer + AS_PATH);
        Map<String, Object> agent = tryGet(client, issuer + PATH);
        if (as == null && agent == null) {
            // Surface the real failure (status or transport) for the document an agent most needs.
            agent = get(client, issuer + PATH);
        }
        String url = issuer + (as != null ? AS_PATH : PATH);
        Object endpoints = agent == null ? null : agent.get("endpoints");
        Map<String, Object> ep = endpoints instanceof Map ? (Map<String, Object>) endpoints : Map.of();

        String token = as != null ? str(as.get("token_endpoint")) : null;
        if (token == null || token.isBlank()) {
            token = str(ep.get("token"));
        }
        if ((token == null || token.isBlank()) && agent != null) {
            token = str(agent.get("token_endpoint"));
        }
        if (token == null || token.isBlank()) {
            throw new AuthFIException(
                url + " advertises no token endpoint, so there is nowhere to authenticate.", 502);
        }

        String backchannel = as != null ? str(as.get("backchannel_authentication_endpoint")) : null;
        if (backchannel == null || backchannel.isBlank()) {
            backchannel = agent == null ? null : str(agent.get("backchannel_authentication_endpoint"));
        }
        if (backchannel == null || backchannel.isBlank()) {
            backchannel = str(ep.get("backchannel_authorize"));
        }

        Map<String, Object> methodsDoc = as != null ? as : agent;
        List<String> methods = strings(methodsDoc.get("token_endpoint_auth_methods_supported"));
        if (!methods.isEmpty() && !methods.contains("private_key_jwt")) {
            throw new AuthFIException(
                "This deployment does not offer private_key_jwt (it advertises " + methods + "), and "
                    + "that is the only agent authentication this SDK implements.", 400);
        }

        return new AgentDiscovery(token, backchannel, methods,
            strings(methodsDoc.get("grant_types_supported")),
            str(ep.get("request_approval")), str(ep.get("approval")));
    }

    private static Map<String, Object> tryGet(HttpClient client, String url) {
        try {
            return get(client, url);
        } catch (AuthFIException e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> get(HttpClient client, String url) {
        Map<String, Object> doc;
        try {
            var req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("Accept", "application/json")
                .GET()
                .build();
            var res = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 400) {
                throw new AuthFIException(
                    "The discovery document could not be read from " + url
                        + " (HTTP " + res.statusCode() + "). Check the tenant and baseUrl.",
                    res.statusCode());
            }
            doc = new Gson().fromJson(res.body(), Map.class);
        } catch (AuthFIException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthFIException("The discovery document could not be read from " + url, e);
        }
        if (doc == null) {
            throw new AuthFIException(url + " did not return a discovery document.", 502);
        }
        return doc;
    }

    private static String str(Object o) {
        return o instanceof String ? (String) o : null;
    }

    @SuppressWarnings("unchecked")
    private static List<String> strings(Object o) {
        if (!(o instanceof List)) return List.of();
        return ((List<Object>) o).stream().map(AgentDiscovery::str).filter(s -> s != null && !s.isBlank()).toList();
    }
}
