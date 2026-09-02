package com.quefly.authfi.ai;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.HashMap;
import java.util.Map;

/**
 * Admin CRUD for the AI agent identity registry.
 * Backed by /manage/{tenant}/v1/ai/agent-registry. Service auth.
 */
public class AIAgentRegistryClient {

    private final HttpTransport http;

    public AIAgentRegistryClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    public String list() {
        return http.get("/ai/agent-registry");
    }

    public String create(String name, String binaryPath, String capsuleName, Map<String, Object> metadata) {
        Map<String, Object> body = new HashMap<>();
        body.put("name", name);
        body.put("binary_path", binaryPath);
        if (capsuleName != null) body.put("capsule_name", capsuleName);
        if (metadata != null) body.put("metadata", metadata);
        return http.post("/ai/agent-registry", body);
    }

    public String get(String registryId) {
        return http.get("/ai/agent-registry/" + registryId);
    }

    public String update(String registryId, Map<String, Object> patch) {
        return http.patch("/ai/agent-registry/" + registryId, patch);
    }

    public String delete(String registryId) {
        return http.delete("/ai/agent-registry/" + registryId);
    }
}
