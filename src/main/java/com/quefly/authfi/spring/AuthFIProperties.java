package com.quefly.authfi.spring;

/**
 * Spring Boot configuration properties.
 *
 * <pre>
 * authfi:
 *   tenant: acme
 *   api-key: sk_live_...
 *   # OR for service mode:
 *   client-id: FIC-abc123
 *   client-secret: FIS-xyz...
 *   base-url: https://api.authfi.app
 * </pre>
 */
public class AuthFIProperties {

    private String tenant;
    private String apiKey;
    private String clientId;
    private String clientSecret;
    private String baseUrl = "https://api.authfi.app";

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
}
