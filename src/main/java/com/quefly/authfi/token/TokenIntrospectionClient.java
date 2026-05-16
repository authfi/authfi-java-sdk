package com.quefly.authfi.token;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.Map;

/**
 * RFC 7662 token introspection + RFC 7009 token revocation.
 * Form-encoded POSTs to /v1/{tenant}/token/{introspect,revoke}. No SDK auth required.
 */
public class TokenIntrospectionClient {

    private final AuthFIConfig config;
    private final HttpTransport http;

    public TokenIntrospectionClient(AuthFIConfig config, HttpTransport http) {
        this.config = config;
        this.http = http;
    }

    /**
     * POST /v1/{tenant}/token/introspect — RFC 7662.
     * Returns JSON with at minimum {@code active: boolean}; if active, also sub/iss/aud/exp/iat/scope.
     */
    public String introspect(String token) {
        return http.formPostAnonymous(
            config.v1Url() + "/token/introspect",
            Map.of("token", token)
        );
    }

    /**
     * POST /v1/{tenant}/token/revoke — RFC 7009.
     * Always returns 200 even if the token is already invalid.
     */
    public String revoke(String token) {
        return http.formPostAnonymous(
            config.v1Url() + "/token/revoke",
            Map.of("token", token)
        );
    }
}
