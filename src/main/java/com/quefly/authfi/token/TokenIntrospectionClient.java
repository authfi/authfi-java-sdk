package com.quefly.authfi.token;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * RFC 7662 token introspection + RFC 7009 token revocation.
 *
 * <p>Form-encoded POSTs to the PROJECT ORIGIN root — {@code https://<tenant>.authfi.io/token/introspect}
 * and {@code .../token/revoke}. These are spec-defined paths, so they live at the root
 * rather than under the AuthFI API prefix, and the tenant is the subdomain rather than a
 * path segment: one origin per project, the same origin {@link AuthFIConfig#issuer()} and
 * {@link AuthFIConfig#jwksUrl()} already use.
 *
 * <p>Both endpoints REQUIRE client authentication (RFC 7662 §2.1, RFC 7009 §2.1): revocation
 * is destructive and introspection is a token-validity oracle, so neither admits an
 * anonymous caller.
 */
public class TokenIntrospectionClient {

    private final AuthFIConfig config;
    private final HttpTransport http;

    public TokenIntrospectionClient(AuthFIConfig config, HttpTransport http) {
        this.config = config;
        this.http = http;
    }

    /**
     * POST https://&lt;tenant&gt;.authfi.io/token/introspect — RFC 7662.
     * Returns JSON with at minimum {@code active: boolean}; if active, also sub/iss/aud/exp/iat/scope.
     *
     * <p>The response is a FLAT RFC 7662 §2.2 body, not the AuthFI {@code {"data":…}}
     * envelope: read {@code active} from the top level. An expired or forged token is a
     * successful response carrying {@code active: false}, not an error.
     */
    public String introspect(String token) {
        return http.formPostAnonymous(
            config.issuer() + "/token/introspect",
            authenticatedForm(token)
        );
    }

    /**
     * POST https://&lt;tenant&gt;.authfi.io/token/revoke — RFC 7009.
     * Always returns 200 with an EMPTY body, even if the token was already invalid —
     * §2.2 requires that so the endpoint cannot be used to probe token validity.
     */
    public String revoke(String token) {
        return http.formPostAnonymous(
            config.issuer() + "/token/revoke",
            authenticatedForm(token)
        );
    }

    /**
     * Builds the form body for both endpoints: the token plus this client's own
     * credentials.
     *
     * <p>Client authentication is REQUIRED on both (RFC 7662 §2.1, RFC 7009 §2.1) and is
     * sent as client_secret_post. Both calls previously went out anonymous, which a
     * conformant server refuses with {@code invalid_client} — they were written against
     * endpoints that did not exist yet, so nothing ever exercised them.
     */
    private Map<String, String> authenticatedForm(String token) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", token);
        form.put("client_id", config.clientId());
        form.put("client_secret", config.clientSecret());
        return form;
    }
}
