package com.quefly.authfi.spring;

/**
 * Spring Boot configuration properties for AuthFI.
 *
 * <pre>
 * # Customer-app — API key (simplest)
 * authfi:
 *   tenant: acme
 *   api-key: sk_live_...
 *
 * # OR customer-app — service identity (OAuth2 client_credentials)
 * authfi:
 *   tenant: acme
 *   client-id: FIC-abc123
 *   client-secret: FIS-xyz...
 *
 * # OR agent-process — AAP (the AuthFI bean becomes agent-mode)
 * authfi:
 *   tenant: acme
 *   agent:
 *     id: agt_abc123
 *     secret: ags_xyz...
 *
 * # Optional permission-catalog auto-sync (default: true if Spring Security on classpath)
 * authfi:
 *   permission-sync:
 *     enabled: true
 * </pre>
 */
public class AuthFIProperties {

    private String tenant;
    private String apiKey;
    private String clientId;
    private String clientSecret;
    private String baseUrl = "https://api.authfi.app";
    private Agent agent = new Agent();
    private PermissionSync permissionSync = new PermissionSync();

    public String getTenant() { return tenant; }
    public void setTenant(String tenant) { this.tenant = tenant; }

    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getBaseUrl() { return baseUrl; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

    public Agent getAgent() { return agent; }
    public void setAgent(Agent agent) { this.agent = agent; }

    public PermissionSync getPermissionSync() { return permissionSync; }
    public void setPermissionSync(PermissionSync permissionSync) { this.permissionSync = permissionSync; }

    public static class Agent {
        private String id;
        private String secret;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }

        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }
    }

    public static class PermissionSync {
        /** Auto-sync the permission catalog by scanning @PreAuthorize annotations at boot. */
        private boolean enabled = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }
}
