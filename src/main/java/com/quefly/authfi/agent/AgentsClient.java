package com.quefly.authfi.agent;

import com.google.gson.Gson;
import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.HashMap;
import java.util.Map;

/**
 * Owner-driven agent registration (NOT the agent acting on its own behalf — that's {@link AgentAuthClient}).
 *
 * <p>The caller (typically a customer's web app) passes the logged-in user's Bearer token.
 * The server records the user as the agent's owner.
 *
 * <pre>
 * AgentCredentials creds = authfi.agents().register(
 *     userJwt, "Inbox triage bot", "Summarizes new mail every 5min", AgentType.DELEGATED);
 * // creds.agentId() + creds.clientSecret() — shown ONCE, hand to the agent's config
 * </pre>
 */
public class AgentsClient {

    private final HttpTransport http;
    private final Gson gson = new Gson();

    public AgentsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    /** POST /{tenant}/v1/agents/register — owner registers an agent. */
    public AgentCredentials register(String userToken, String name, String description, AgentType type) {
        Map<String, Object> body = new HashMap<>();
        body.put("name", name);
        if (description != null) body.put("description", description);
        body.put("type", type.wireValue());

        String json = http.postAsUser(userToken, "/agents/register", body);
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = gson.fromJson(json, Map.class);

        Number created = (Number) resp.get("created_at");
        return new AgentCredentials(
            asString(resp.get("agent_id")),
            asString(resp.get("client_secret")),
            asString(resp.get("type")),
            asString(resp.get("owner_user_id")),
            created != null ? created.longValue() : 0L,
            asString(resp.get("warning"))
        );
    }

    private static String asString(Object o) {
        return o != null ? o.toString() : null;
    }
}
