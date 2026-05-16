package com.quefly.authfi.agent;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.Map;

/**
 * End-user portal for managing the agents one has authorized to act on one's behalf.
 * Backed by /v1/{tenant}/me/agents/* — all routes take the user's Bearer token.
 */
public class MyAgentsClient {

    private final HttpTransport http;

    public MyAgentsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    /** GET /me/agents — list of agents the user has authorized. */
    public String list(String userToken) {
        return http.getAsUser(userToken, "/me/agents");
    }

    /** GET /me/agents/approvals — pending approval requests across all the user's agents. */
    public String approvals(String userToken) {
        return http.getAsUser(userToken, "/me/agents/approvals");
    }

    /** POST /me/agents/approvals/{approvalId} — approve or deny a pending request. */
    public String resolve(String userToken, String approvalId, boolean approved) {
        return http.postAsUser(userToken,
            "/me/agents/approvals/" + approvalId,
            Map.of("approved", approved));
    }

    /** POST /me/agents/{agentId}/revoke — revoke an agent the user previously authorized. */
    public String revoke(String userToken, String agentId) {
        return http.postAsUser(userToken,
            "/me/agents/" + agentId + "/revoke",
            Map.of());
    }

    /** GET /me/agents/{agentId}/activity — audit trail for a specific agent. */
    public String activity(String userToken, String agentId) {
        return http.getAsUser(userToken, "/me/agents/" + agentId + "/activity");
    }
}
