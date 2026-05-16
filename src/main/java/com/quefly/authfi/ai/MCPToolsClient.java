package com.quefly.authfi.ai;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.HashMap;
import java.util.Map;

/**
 * MCP tool catalog — the registry of tools an agent may invoke.
 * Backed by /manage/v1/{tenant}/mcp/tools. Service auth.
 */
public class MCPToolsClient {

    private final HttpTransport http;

    public MCPToolsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    public String list() {
        return http.get("/mcp/tools");
    }

    public String create(String name, String description, Map<String, Object> schema, boolean enabled) {
        Map<String, Object> body = new HashMap<>();
        body.put("name", name);
        body.put("description", description);
        if (schema != null) body.put("schema", schema);
        body.put("enabled", enabled);
        return http.post("/mcp/tools", body);
    }

    public String get(String toolId) {
        return http.get("/mcp/tools/" + toolId);
    }

    public String update(String toolId, Map<String, Object> patch) {
        return http.patch("/mcp/tools/" + toolId, patch);
    }

    public String delete(String toolId) {
        return http.delete("/mcp/tools/" + toolId);
    }
}
