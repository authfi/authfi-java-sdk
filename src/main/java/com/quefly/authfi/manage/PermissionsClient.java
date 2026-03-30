package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Permission management and auto-sync.
 *
 * Permissions discovered via require() calls are automatically
 * collected and synced to AuthFI on sync().
 */
public class PermissionsClient {

    private final HttpTransport http;
    private final ConcurrentHashMap<String, String> registered = new ConcurrentHashMap<>();

    public PermissionsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    /**
     * Register a permission for sync. Call this from your route definitions.
     * Collected permissions are pushed to AuthFI when sync() is called.
     */
    public void register(String name, String description) {
        registered.put(name, description != null ? description : "");
    }

    /** Register a permission without description. */
    public void register(String name) {
        register(name, null);
    }

    /**
     * Sync all registered permissions to AuthFI.
     * Call once on application startup.
     */
    public void sync() {
        if (registered.isEmpty()) return;

        List<Map<String, String>> perms = registered.entrySet().stream()
            .map(e -> {
                var m = new java.util.HashMap<String, String>();
                m.put("name", e.getKey());
                if (!e.getValue().isEmpty()) m.put("description", e.getValue());
                return (Map<String, String>) m;
            })
            .toList();

        http.put("/permissions/sync", Map.of("permissions", perms));
    }

    /** List all permissions. */
    public String list() {
        return http.get("/permissions");
    }

    /** Create a permission. */
    public String create(String name, String description) {
        return http.post("/permissions", Map.of("name", name, "description", description));
    }

    /** Delete a permission. */
    public String delete(String permissionId) {
        return http.delete("/permissions/" + permissionId);
    }

    /** List roles. */
    public String listRoles() {
        return http.get("/roles");
    }

    /** Create a role. */
    public String createRole(String name, String description) {
        return http.post("/roles", Map.of("name", name, "description", description));
    }

    /** Assign permissions to a role. */
    public String assignToRole(String roleId, String... permissionIds) {
        return http.post("/roles/" + roleId + "/permissions", Map.of("permissions", permissionIds));
    }
}
