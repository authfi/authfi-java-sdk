package com.quefly.authfi.ai;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.HashMap;
import java.util.Map;

/**
 * Admin view of AI run lifecycle — create, list, taint, restore, revoke.
 * Backed by /manage/v1/{tenant}/ai/runs. Service auth.
 */
public class AIRunsClient {

    private final HttpTransport http;

    public AIRunsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    public String list() {
        return http.get("/ai/runs");
    }

    public String create(String binaryPath, String tenantId, String agentId, int pid,
                         String cmd, Map<String, Object> context) {
        Map<String, Object> body = new HashMap<>();
        body.put("binary_path", binaryPath);
        body.put("tenant_id", tenantId);
        body.put("agent_id", agentId);
        body.put("pid", pid);
        body.put("cmd", cmd);
        if (context != null) body.put("context", context);
        return http.post("/ai/runs", body);
    }

    public String get(String runId) {
        return http.get("/ai/runs/" + runId);
    }

    public String update(String runId, Map<String, Object> patch) {
        return http.patch("/ai/runs/" + runId, patch);
    }

    public String taint(String runId, String reason, Map<String, Object> context) {
        Map<String, Object> body = new HashMap<>();
        body.put("reason", reason);
        if (context != null) body.put("context", context);
        return http.post("/ai/runs/" + runId + "/taint", body);
    }

    public String restore(String runId) {
        return http.post("/ai/runs/" + runId + "/restore", Map.of());
    }

    public String revoke(String runId) {
        return http.post("/ai/runs/" + runId + "/revoke", Map.of());
    }
}
