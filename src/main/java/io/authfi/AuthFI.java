package io.authfi;

import io.authfi.agent.AgentAuthClient;
import io.authfi.agent.AgentsClient;
import io.authfi.agent.MyAgentsClient;
import io.authfi.ai.AIAgentRegistryClient;
import io.authfi.ai.AIRunsClient;
import io.authfi.ai.MCPCallsClient;
import io.authfi.ai.MCPToolsClient;
import io.authfi.auth.TokenVerifier;
import io.authfi.connect.ConnectClient;
import io.authfi.manage.AuditLogsClient;
import io.authfi.manage.InvitationsClient;
import io.authfi.manage.MFAClient;
import io.authfi.manage.MeClient;
import io.authfi.manage.OrgsClient;
import io.authfi.manage.PermissionsClient;
import io.authfi.manage.SessionsClient;
import io.authfi.manage.UsersClient;
import io.authfi.token.DiscoveryClient;
import io.authfi.token.TokenIntrospectionClient;

/**
 * AuthFI Java SDK — entry point.
 *
 * <pre>
 * // Customer web app (end-user JWT verification + management API)
 * AuthFI authfi = AuthFI.client().tenant("acme").apiKey("sk_live_...").build();
 *
 * // Customer service (M2M; OAuth2 client_credentials)
 * AuthFI authfi = AuthFI.service()
 *     .tenant("acme")
 *     .clientId("FIC-abc123")
 *     .clientSecret("FIS-xyz...")
 *     .build();
 *
 * // Agent process (AuthFI Agent Profile — agent acts on its own behalf, owner pre-registered it)
 * AuthFI agent = AuthFI.agent().fromEnv().build();
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
    private volatile MeClient meClient;
    private volatile SessionsClient sessionsClient;
    private volatile MFAClient mfaClient;
    private volatile AuditLogsClient auditLogsClient;
    private volatile InvitationsClient invitationsClient;
    private volatile TokenIntrospectionClient tokenIntrospectionClient;
    private volatile DiscoveryClient discoveryClient;
    private volatile AgentsClient agentsClient;
    private volatile MyAgentsClient myAgentsClient;
    private volatile AgentAuthClient agentAuthClient;
    private volatile AIAgentRegistryClient aiAgentRegistryClient;
    private volatile AIRunsClient aiRunsClient;
    private volatile MCPToolsClient mcpToolsClient;
    private volatile MCPCallsClient mcpCallsClient;

    AuthFI(AuthFIConfig config) {
        this.config = config;
        this.http = new HttpTransport(config);
    }

    // === Factories ===

    public static Builder client() {
        return new Builder(AuthFIConfig.AuthMode.API_KEY);
    }

    public static Builder service() {
        return new Builder(AuthFIConfig.AuthMode.CLIENT_CREDENTIALS);
    }

    public static AgentBuilder agent() {
        return new AgentBuilder();
    }

    // === Modules (lazy init, thread-safe) ===

    /** Token verification — JWKS + RS256 (backed by Nimbus). */
    public TokenVerifier auth() {
        if (tokenVerifier == null) synchronized (this) {
            if (tokenVerifier == null) tokenVerifier = new TokenVerifier(config);
        }
        return tokenVerifier;
    }

    /** Cloud credentials — GCP, AWS, Azure, OCI. */
    public ConnectClient connect() {
        if (connectClient == null) synchronized (this) {
            if (connectClient == null) connectClient = new ConnectClient(config, http);
        }
        return connectClient;
    }

    /** User management. */
    public UsersClient users() {
        if (usersClient == null) synchronized (this) {
            if (usersClient == null) usersClient = new UsersClient(config, http);
        }
        return usersClient;
    }

    /** Organization management. */
    public OrgsClient orgs() {
        if (orgsClient == null) synchronized (this) {
            if (orgsClient == null) orgsClient = new OrgsClient(config, http);
        }
        return orgsClient;
    }

    /** Permission sync and management. */
    public PermissionsClient permissions() {
        if (permissionsClient == null) synchronized (this) {
            if (permissionsClient == null) permissionsClient = new PermissionsClient(config, http);
        }
        return permissionsClient;
    }

    /** Current-user (/me, /userinfo, change password) — caller passes user's access token. */
    public MeClient me() {
        if (meClient == null) synchronized (this) {
            if (meClient == null) meClient = new MeClient(config, http);
        }
        return meClient;
    }

    /** Session lifecycle — both /me/sessions (user token) and admin per-user. */
    public SessionsClient sessions() {
        if (sessionsClient == null) synchronized (this) {
            if (sessionsClient == null) sessionsClient = new SessionsClient(config, http);
        }
        return sessionsClient;
    }

    /** MFA factor enrollment / verification — user token. */
    public MFAClient mfa() {
        if (mfaClient == null) synchronized (this) {
            if (mfaClient == null) mfaClient = new MFAClient(config, http);
        }
        return mfaClient;
    }

    /** Tenant audit log search. */
    public AuditLogsClient auditLogs() {
        if (auditLogsClient == null) synchronized (this) {
            if (auditLogsClient == null) auditLogsClient = new AuditLogsClient(config, http);
        }
        return auditLogsClient;
    }

    /** Programmatic user invitations (backend currently in development — see InvitationsClient docs). */
    public InvitationsClient invitations() {
        if (invitationsClient == null) synchronized (this) {
            if (invitationsClient == null) invitationsClient = new InvitationsClient(config, http);
        }
        return invitationsClient;
    }

    /** RFC 7662 token introspection + RFC 7009 revocation. */
    public TokenIntrospectionClient tokenIntrospection() {
        if (tokenIntrospectionClient == null) synchronized (this) {
            if (tokenIntrospectionClient == null)
                tokenIntrospectionClient = new TokenIntrospectionClient(config, http);
        }
        return tokenIntrospectionClient;
    }

    /** OIDC + SMART + agent-auth discovery (.well-known). */
    public DiscoveryClient discovery() {
        if (discoveryClient == null) synchronized (this) {
            if (discoveryClient == null) discoveryClient = new DiscoveryClient(config, http);
        }
        return discoveryClient;
    }

    /** Owner-driven agent registration (POST /{tenant}/v1/agents/register, requires user JWT). */
    public AgentsClient agents() {
        if (agentsClient == null) synchronized (this) {
            if (agentsClient == null) agentsClient = new AgentsClient(config, http);
        }
        return agentsClient;
    }

    /** End-user portal for managing one's own delegated agents (/me/agents/*). */
    public MyAgentsClient myAgents() {
        if (myAgentsClient == null) synchronized (this) {
            if (myAgentsClient == null) myAgentsClient = new MyAgentsClient(config, http);
        }
        return myAgentsClient;
    }

    /** AuthFI Agent Profile — agent self-service: token, request-approval, poll. Only valid in AGENT_CREDENTIALS mode. */
    public AgentAuthClient agentAuth() {
        if (agentAuthClient == null) synchronized (this) {
            if (agentAuthClient == null) agentAuthClient = new AgentAuthClient(config, http);
        }
        return agentAuthClient;
    }

    /** Admin: AI agent identity registry CRUD. */
    public AIAgentRegistryClient aiAgentRegistry() {
        if (aiAgentRegistryClient == null) synchronized (this) {
            if (aiAgentRegistryClient == null)
                aiAgentRegistryClient = new AIAgentRegistryClient(config, http);
        }
        return aiAgentRegistryClient;
    }

    /** Admin: AI run lifecycle (create, list, taint, restore, revoke). */
    public AIRunsClient aiRuns() {
        if (aiRunsClient == null) synchronized (this) {
            if (aiRunsClient == null) aiRunsClient = new AIRunsClient(config, http);
        }
        return aiRunsClient;
    }

    /** Admin: MCP tool catalog. */
    public MCPToolsClient mcpTools() {
        if (mcpToolsClient == null) synchronized (this) {
            if (mcpToolsClient == null) mcpToolsClient = new MCPToolsClient(config, http);
        }
        return mcpToolsClient;
    }

    /** Admin: MCP call audit. */
    public MCPCallsClient mcpCalls() {
        if (mcpCallsClient == null) synchronized (this) {
            if (mcpCallsClient == null) mcpCallsClient = new MCPCallsClient(config, http);
        }
        return mcpCallsClient;
    }

    /** Get a service token (client_credentials grant). */
    public String token(String... scopes) {
        return http.clientCredentialsToken(scopes);
    }

    /** Exchange a user token for a scoped token (RFC 8693 on-behalf-of). */
    public OnBehalfOf onBehalfOf(String userAccessToken) {
        return new OnBehalfOf(config, http, userAccessToken);
    }

    public AuthFIConfig getConfig() {
        return config;
    }

    // === Builders ===

    /** Builder for customer-facing modes (client / service). */
    public static class Builder {
        private final AuthFIConfig.AuthMode authMode;
        private String tenant;
        private String apiKey;
        private String clientId;
        private String clientSecret;
        private String baseUrl = "https://api.authfi.io";

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
            return new AuthFI(new AuthFIConfig(
                tenant, apiKey, clientId, clientSecret,
                null, null, baseUrl, authMode));
        }
    }

    /** Builder for agent-process mode (AuthFI Agent Profile). */
    public static class AgentBuilder {
        private String tenant;
        private String agentId;
        private String agentSecret;
        private String agentPrivateKey;
        private String agentKeyId;
        private String baseUrl = "https://api.authfi.io";

        public AgentBuilder tenant(String tenant) { this.tenant = tenant; return this; }
        public AgentBuilder agentId(String agentId) { this.agentId = agentId; return this; }
        public AgentBuilder agentSecret(String agentSecret) { this.agentSecret = agentSecret; return this; }
        public AgentBuilder baseUrl(String baseUrl) { this.baseUrl = baseUrl; return this; }

        /** The agent's Ed25519 private key, PKCS#8 PEM. Enables private_key_jwt. */
        public AgentBuilder agentPrivateKey(String pem) { this.agentPrivateKey = pem; return this; }

        /** The kid registered with the public JWK. Required with {@link #agentPrivateKey}. */
        public AgentBuilder agentKeyId(String kid) { this.agentKeyId = kid; return this; }

        /** Populate tenant, agentId, agentSecret, and optional baseUrl from environment variables. */
        public AgentBuilder fromEnv() {
            String t = System.getenv("AUTHFI_TENANT");
            String id = System.getenv("AUTHFI_AGENT_ID");
            String secret = System.getenv("AUTHFI_AGENT_SECRET");
            String base = System.getenv("AUTHFI_BASE_URL");
            // The key may be supplied inline or by path. A path is the safer habit for a private
            // key — an env var holding one leaks into `ps`, crash dumps and child processes.
            String key = System.getenv("AUTHFI_AGENT_PRIVATE_KEY");
            String keyFile = System.getenv("AUTHFI_AGENT_PRIVATE_KEY_FILE");
            String kid = System.getenv("AUTHFI_AGENT_KEY_ID");
            if (t != null) this.tenant = t;
            if (id != null) this.agentId = id;
            if (secret != null) this.agentSecret = secret;
            if (base != null) this.baseUrl = base;
            if (key != null) this.agentPrivateKey = key;
            if (keyFile != null && !keyFile.isBlank()) {
                try {
                    this.agentPrivateKey = java.nio.file.Files.readString(java.nio.file.Path.of(keyFile));
                } catch (java.io.IOException e) {
                    throw new AuthFIException("Could not read AUTHFI_AGENT_PRIVATE_KEY_FILE: " + keyFile, e);
                }
            }
            if (kid != null) this.agentKeyId = kid;
            return this;
        }

        public AuthFI build() {
            if (tenant == null || tenant.isBlank()) {
                throw new IllegalArgumentException("tenant is required (or set AUTHFI_TENANT)");
            }
            if (agentId == null || agentId.isBlank()) {
                throw new IllegalArgumentException("agentId is required (or set AUTHFI_AGENT_ID)");
            }
            boolean hasKey = agentPrivateKey != null && !agentPrivateKey.isBlank()
                && agentKeyId != null && !agentKeyId.isBlank();
            // A key alone is not a credential — without the kid the server cannot select the
            // verifying key, so half-configured is refused HERE rather than at the first call.
            if (!hasKey && agentPrivateKey != null && !agentPrivateKey.isBlank()) {
                throw new IllegalArgumentException(
                    "agentKeyId is required with agentPrivateKey (or set AUTHFI_AGENT_KEY_ID)");
            }
            if (!hasKey && (agentSecret == null || agentSecret.isBlank())) {
                throw new IllegalArgumentException(
                    "An agent credential is required: agentPrivateKey + agentKeyId "
                        + "(AUTHFI_AGENT_PRIVATE_KEY[_FILE] + AUTHFI_AGENT_KEY_ID), or for a legacy "
                        + "agent agentSecret (AUTHFI_AGENT_SECRET). An agent registered with a "
                        + "public JWK is issued no secret.");
            }
            return new AuthFI(new AuthFIConfig(
                tenant, null, null, null,
                agentId, agentSecret, agentPrivateKey, agentKeyId, baseUrl,
                AuthFIConfig.AuthMode.AGENT_CREDENTIALS));
        }
    }

    /** On-behalf-of token-exchange builder (RFC 8693). */
    public static class OnBehalfOf {
        private final HttpTransport http;
        private final String subjectToken;

        OnBehalfOf(AuthFIConfig config, HttpTransport http, String subjectToken) {
            this.http = http;
            this.subjectToken = subjectToken;
        }

        public String token(String... scopes) {
            return http.tokenExchange(subjectToken, scopes);
        }
    }
}
