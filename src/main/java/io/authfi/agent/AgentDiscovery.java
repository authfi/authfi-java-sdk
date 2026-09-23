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
 * The AI Agent Auth Protocol discovery document — the only authority on where the endpoints are.
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

    private final String tokenEndpoint;
    private final String backchannelEndpoint;
    private final List<String> authMethods;
    private final List<String> grantTypes;

    private AgentDiscovery(String tokenEndpoint, String backchannelEndpoint,
                           List<String> authMethods, List<String> grantTypes) {
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

    public List<String> tokenEndpointAuthMethodsSupported() {
        return authMethods;
    }

    public List<String> grantTypesSupported() {
        return grantTypes;
    }

    /**
     * Read the document from {@code issuer + /.well-known/agent-configuration}.
     *
     * @throws AuthFIException when it cannot be read, is not a document, or advertises no
     *         {@code private_key_jwt} — each with the issuer named, because "discovery failed" on
     *         its own sends people to the wrong place.
     */
    @SuppressWarnings("unchecked")
    public static AgentDiscovery fetch(HttpClient client, String issuer) {
        String url = issuer + PATH;
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
                    "The agent discovery document could not be read from " + url
                        + " (HTTP " + res.statusCode() + "). Check the tenant and baseUrl.",
                    res.statusCode());
            }
            doc = new Gson().fromJson(res.body(), Map.class);
        } catch (AuthFIException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthFIException("The agent discovery document could not be read from " + url, e);
        }
        if (doc == null) {
            throw new AuthFIException(url + " did not return a discovery document.", 502);
        }

        Object endpoints = doc.get("endpoints");
        String token = endpoints instanceof Map ? str(((Map<String, Object>) endpoints).get("token")) : null;
        if (token == null || token.isBlank()) {
            // Fall back to the top-level spelling before giving up — the document carries the
            // backchannel endpoint at the top level too, so both shapes exist in the wild.
            token = str(doc.get("token_endpoint"));
        }
        if (token == null || token.isBlank()) {
            throw new AuthFIException(
                url + " advertises no token endpoint, so there is nowhere to authenticate.", 502);
        }

        String backchannel = str(doc.get("backchannel_authentication_endpoint"));
        if ((backchannel == null || backchannel.isBlank()) && endpoints instanceof Map) {
            backchannel = str(((Map<String, Object>) endpoints).get("backchannel_authorize"));
        }

        List<String> methods = strings(doc.get("token_endpoint_auth_methods_supported"));
        if (!methods.isEmpty() && !methods.contains("private_key_jwt")) {
            throw new AuthFIException(
                "This deployment does not offer private_key_jwt (it advertises " + methods + "), and "
                    + "that is the only agent authentication this SDK implements.", 400);
        }

        return new AgentDiscovery(token, backchannel, methods, strings(doc.get("grant_types_supported")));
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
