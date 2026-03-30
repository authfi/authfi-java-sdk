package com.quefly.authfi;

import com.quefly.authfi.auth.TokenVerifier;
import com.quefly.authfi.connect.ConnectClient;
import com.quefly.authfi.manage.UsersClient;
import com.quefly.authfi.manage.OrgsClient;
import com.quefly.authfi.manage.PermissionsClient;

/**
 * AuthFI Java SDK — entry point.
 *
 * <pre>
 * // User-facing app
 * AuthFI authfi = AuthFI.client()
 *     .tenant("acme")
 *     .apiKey("sk_live_...")
 *     .build();
 *
 * // Service (M2M)
 * AuthFI authfi = AuthFI.service()
 *     .tenant("acme")
 *     .clientId("FIC-abc123")
 *     .clientSecret("FIS-xyz...")
 *     .build();
 * </pre>
 */
public class AuthFI {

    private final AuthFIConfig config;
    private final HttpTransport http;

    private volatile TokenVerifier tokenVerifier;
    private volatile ConnectClient connectClient;
    private volatile UsersClient usersClient;
    private volatile OrgsClient orgsClient;
    private volatile PermissionsClient permissionsClient;

    AuthFI(AuthFIConfig config) {
        this.config = config;
        this.http = new HttpTransport(config);
    }

    // --- Factory ---

    public static Builder client() {
        return new Builder(AuthFIConfig.AuthMode.API_KEY);
    }

    public static Builder service() {
        return new Builder(AuthFIConfig.AuthMode.CLIENT_CREDENTIALS);
    }

    // --- Modules (lazy init) ---

    /** Token verification — JWKS + RS256. */
    public TokenVerifier auth() {
        if (tokenVerifier == null) {
            synchronized (this) {
                if (tokenVerifier == null) {
                    tokenVerifier = new TokenVerifier(config);
                }
            }
        }
        return tokenVerifier;
    }

    /** Cloud credentials — GCP, AWS, Azure, OCI. */
    public ConnectClient connect() {
        if (connectClient == null) {
            synchronized (this) {
                if (connectClient == null) {
                    connectClient = new ConnectClient(config, http);
                }
            }
        }
        return connectClient;
    }

    /** User management. */
    public UsersClient users() {
        if (usersClient == null) {
            synchronized (this) {
                if (usersClient == null) {
                    usersClient = new UsersClient(config, http);
                }
            }
        }
        return usersClient;
    }

    /** Organization management. */
    public OrgsClient orgs() {
        if (orgsClient == null) {
            synchronized (this) {
                if (orgsClient == null) {
                    orgsClient = new OrgsClient(config, http);
                }
            }
        }
        return orgsClient;
    }

    /** Permission sync and management. */
    public PermissionsClient permissions() {
        if (permissionsClient == null) {
            synchronized (this) {
                if (permissionsClient == null) {
                    permissionsClient = new PermissionsClient(config, http);
                }
            }
        }
        return permissionsClient;
    }

    /** Get a service token (client_credentials grant). */
    public String token(String... scopes) {
        return http.clientCredentialsToken(scopes);
    }

    /** Exchange a user token for a scoped token (on-behalf-of). */
    public OnBehalfOf onBehalfOf(String userAccessToken) {
        return new OnBehalfOf(config, http, userAccessToken);
    }

    /** Get the config. */
    public AuthFIConfig getConfig() {
        return config;
    }

    // --- Builder ---

    public static class Builder {
        private final AuthFIConfig.AuthMode authMode;
        private String tenant;
        private String apiKey;
        private String clientId;
        private String clientSecret;
        private String baseUrl = "https://api.authfi.app";

        Builder(AuthFIConfig.AuthMode authMode) {
            this.authMode = authMode;
        }

        public Builder tenant(String tenant) { this.tenant = tenant; return this; }
        public Builder apiKey(String apiKey) { this.apiKey = apiKey; return this; }
        public Builder clientId(String clientId) { this.clientId = clientId; return this; }
        public Builder clientSecret(String clientSecret) { this.clientSecret = clientSecret; return this; }
        public Builder baseUrl(String baseUrl) { this.baseUrl = baseUrl; return this; }

        public AuthFI build() {
            if (tenant == null || tenant.isBlank()) throw new IllegalArgumentException("tenant is required");
            if (authMode == AuthFIConfig.AuthMode.API_KEY && (apiKey == null || apiKey.isBlank())) {
                throw new IllegalArgumentException("apiKey is required for client mode");
            }
            if (authMode == AuthFIConfig.AuthMode.CLIENT_CREDENTIALS) {
                if (clientId == null || clientSecret == null) {
                    throw new IllegalArgumentException("clientId and clientSecret are required for service mode");
                }
            }
            return new AuthFI(new AuthFIConfig(tenant, apiKey, clientId, clientSecret, baseUrl, authMode));
        }
    }

    // --- On-Behalf-Of ---

    public static class OnBehalfOf {
        private final AuthFIConfig config;
        private final HttpTransport http;
        private final String subjectToken;

        OnBehalfOf(AuthFIConfig config, HttpTransport http, String subjectToken) {
            this.config = config;
            this.http = http;
            this.subjectToken = subjectToken;
        }

        public String token(String... scopes) {
            return http.tokenExchange(subjectToken, scopes);
        }
    }
}
