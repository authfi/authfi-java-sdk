package com.quefly.authfi.ai;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.Map;

/**
 * Audit view of MCP tool calls.
 * Backed by /manage/v1/{tenant}/mcp/calls. Service auth.
 */
public class MCPCallsClient {

    private final HttpTransport http;

    public MCPCallsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    public String list() {
        return http.get("/mcp/calls");
    }

    public String get(String callId) {
        return http.get("/mcp/calls/" + callId);
    }

    public String update(String callId, Map<String, Object> patch) {
        return http.patch("/mcp/calls/" + callId, patch);
    }
}
