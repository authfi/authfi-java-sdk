package com.quefly.authfi.connect;

import com.google.gson.Gson;
import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.Map;

/**
 * AuthFI Connect — exchange AuthFI identity for cloud credentials.
 * Supports GCP, AWS, Azure, OCI.
 */
public class ConnectClient {

    private final AuthFIConfig config;
    private final HttpTransport http;
    private final Gson gson = new Gson();

    public ConnectClient(AuthFIConfig config, HttpTransport http) {
        this.config = config;
        this.http = http;
    }

    /** Get temporary GCP credentials for a role mapping. */
    public CloudCredentials gcp(String roleMapping) {
        return exchange("gcp", roleMapping, null);
    }

    /** Get temporary AWS credentials for a role mapping. */
    public CloudCredentials aws(String roleMapping) {
        return exchange("aws", roleMapping, null);
    }

    /** Get temporary Azure credentials for a role mapping. */
    public CloudCredentials azure(String roleMapping) {
        return exchange("azure", roleMapping, null);
    }

    /** Get temporary OCI credentials for a role mapping. */
    public CloudCredentials oci(String roleMapping) {
        return exchange("oci", roleMapping, null);
    }

    /** Get cloud credentials with specific scopes. */
    public CloudCredentials exchange(String provider, String roleMapping, String[] scopes) {
        var body = Map.of(
            "provider", provider,
            "role_mapping", roleMapping,
            "scopes", scopes != null ? scopes : new String[0]
        );
        String response = http.post("/connect/exchange", body);
        return gson.fromJson(response, CloudCredentials.class);
    }

    /** List configured cloud accounts. */
    public String listAccounts() {
        return http.get("/connect/accounts");
    }

    /** List role mappings for a cloud account. */
    public String listRoleMappings(String accountId) {
        return http.get("/connect/accounts/" + accountId + "/mappings");
    }
}
