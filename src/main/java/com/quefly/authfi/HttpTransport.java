package com.quefly.authfi;

import com.google.gson.Gson;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** HTTP client for AuthFI API calls. */
public class HttpTransport {

    private final AuthFIConfig config;
    private final HttpClient client;
    private final Gson gson = new Gson();

    private volatile String cachedToken;
    private volatile long tokenExpiry;

    private volatile String cachedAgentToken;
    private volatile long agentTokenExpiry;
    private volatile Set<String> cachedAgentCapabilities = Collections.emptySet();

    public HttpTransport(AuthFIConfig config) {
        this.config = config;
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    // === Management API — service auth (X-API-Key or client_credentials Bearer) ===

    public String get(String path) {
        return manageRequest("GET", path, null);
    }

    public String post(String path, Object body) {
        return manageRequest("POST", path, body);
    }

    public String put(String path, Object body) {
        return manageRequest("PUT", path, body);
    }

    public String delete(String path) {
        return manageRequest("DELETE", path, null);
    }

    public String patch(String path, Object body) {
        return manageRequest("PATCH", path, body);
    }

    // === End-user-context — caller passes the user's access token ===

    public String getAsUser(String userToken, String path) {
        return userRequest("GET", userToken, path, null);
    }

    public String postAsUser(String userToken, String path, Object body) {
        return userRequest("POST", userToken, path, body);
    }

    public String deleteAsUser(String userToken, String path) {
        return userRequest("DELETE", userToken, path, null);
    }

    // === Agent-context — uses cached agent token from /{tenant}/v1/agents/token ===

    public String getAsAgent(String path) {
        return agentRequest("GET", path, null);
    }

    public String postAsAgent(String path, Object body) {
        return agentRequest("POST", path, body);
    }

    // === Anonymous — no auth header ===

    public String getAnonymous(String absoluteUrl) {
        var req = HttpRequest.newBuilder()
            .uri(URI.create(absoluteUrl))
            .GET()
            .build();
        return send(req, "GET " + absoluteUrl);
    }

    public String formPostAnonymous(String absoluteUrl, Map<String, String> formParams) {
        StringBuilder body = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> e : formParams.entrySet()) {
            if (e.getValue() == null) continue;
            if (!first) body.append('&');
            body.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                .append('=')
                .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
            first = false;
        }
        var req = HttpRequest.newBuilder()
            .uri(URI.create(absoluteUrl))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
            .build();
        return send(req, "POST " + absoluteUrl);
    }

    // === OAuth2 — customer service identity (/{tenant}/v1/oauth/token) ===

    public String clientCredentialsToken(String... scopes) {
        if (cachedToken != null && System.currentTimeMillis() / 1000 < tokenExpiry - 60) {
            return cachedToken;
        }

        String scope = String.join(" ", scopes);
        String body = "grant_type=client_credentials"
            + "&client_id=" + URLEncoder.encode(config.clientId(), StandardCharsets.UTF_8)
            + "&client_secret=" + URLEncoder.encode(config.clientSecret(), StandardCharsets.UTF_8);
        if (!scope.isBlank()) {
            body += "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8);
        }

        var req = HttpRequest.newBuilder()
            .uri(URI.create(config.tokenEndpoint()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        try {
            var res = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 400) {
                throw new AuthFIException("Token request failed: " + res.body(), res.statusCode());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenMap = gson.fromJson(res.body(), Map.class);
            cachedToken = (String) tokenMap.get("access_token");
            Number expiresIn = (Number) tokenMap.getOrDefault("expires_in", 3600);
            tokenExpiry = System.currentTimeMillis() / 1000 + expiresIn.longValue();
            return cachedToken;
        } catch (AuthFIException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthFIException("Token request failed", e);
        }
    }

    public String tokenExchange(String subjectToken, String... scopes) {
        String body = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
            + "&subject_token=" + URLEncoder.encode(subjectToken, StandardCharsets.UTF_8)
            + "&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
            + "&client_id=" + URLEncoder.encode(config.clientId(), StandardCharsets.UTF_8)
            + "&client_secret=" + URLEncoder.encode(config.clientSecret(), StandardCharsets.UTF_8);
        String scope = String.join(" ", scopes);
        if (!scope.isBlank()) {
            body += "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8);
        }

        var req = HttpRequest.newBuilder()
            .uri(URI.create(config.tokenEndpoint()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        try {
            var res = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 400) {
                throw new AuthFIException("Token exchange failed: " + res.body(), res.statusCode());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenMap = gson.fromJson(res.body(), Map.class);
            return (String) tokenMap.get("access_token");
        } catch (AuthFIException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthFIException("Token exchange failed", e);
        }
    }

    // === AAP — agent identity (/{tenant}/v1/agents/token) ===

    /**
     * Fetch (or return cached) the agent's access token via client_credentials
     * against /{tenant}/v1/agents/token. Also populates {@link #agentCapabilities()}.
     */
    public String agentToken() {
        if (cachedAgentToken != null && System.currentTimeMillis() / 1000 < agentTokenExpiry - 60) {
            return cachedAgentToken;
        }

        if (config.agentId() == null || config.agentSecret() == null) {
            throw new AuthFIException("agent_id and agent_secret are required for agent calls", 401);
        }

        String body = "grant_type=client_credentials"
            + "&client_id=" + URLEncoder.encode(config.agentId(), StandardCharsets.UTF_8)
            + "&client_secret=" + URLEncoder.encode(config.agentSecret(), StandardCharsets.UTF_8);

        var req = HttpRequest.newBuilder()
            .uri(URI.create(config.agentTokenEndpoint()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        try {
            var res = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 400) {
                throw new AuthFIException("Agent token request failed: " + res.body(), res.statusCode());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenMap = gson.fromJson(res.body(), Map.class);
            cachedAgentToken = (String) tokenMap.get("access_token");
            Number expiresIn = (Number) tokenMap.getOrDefault("expires_in", 3600);
            agentTokenExpiry = System.currentTimeMillis() / 1000 + expiresIn.longValue();

            Object caps = tokenMap.get("capabilities");
            if (caps instanceof List<?> capList) {
                cachedAgentCapabilities = Set.copyOf(
                    capList.stream().map(Object::toString).toList()
                );
            }
            return cachedAgentToken;
        } catch (AuthFIException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthFIException("Agent token request failed", e);
        }
    }

    /** Capabilities granted to this agent, populated as a side effect of {@link #agentToken()}. */
    public Set<String> agentCapabilities() {
        if (cachedAgentCapabilities.isEmpty() && cachedAgentToken == null) {
            agentToken();
        }
        return cachedAgentCapabilities;
    }

    // === Internal ===

    private String manageRequest(String method, String path, Object body) {
        String url = config.manageUrl() + path;
        var builder = HttpRequest.newBuilder().uri(URI.create(url));

        if (config.authMode() == AuthFIConfig.AuthMode.API_KEY) {
            builder.header("X-API-Key", config.apiKey());
        } else if (config.authMode() == AuthFIConfig.AuthMode.CLIENT_CREDENTIALS) {
            builder.header("Authorization", "Bearer " + clientCredentialsToken());
        } else {
            throw new AuthFIException(
                "Management API requires client or service mode (current mode: " + config.authMode() + ")",
                403);
        }
        builder.header("Content-Type", "application/json");

        HttpRequest.BodyPublisher publisher = body != null
            ? HttpRequest.BodyPublishers.ofString(gson.toJson(body))
            : HttpRequest.BodyPublishers.noBody();
        builder.method(method, publisher);

        return send(builder.build(), method + " " + url);
    }

    private String userRequest(String method, String userToken, String path, Object body) {
        if (userToken == null || userToken.isBlank()) {
            throw new AuthFIException("user access token is required", 401);
        }
        String url = config.v1Url() + path;
        var builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Authorization", "Bearer " + userToken)
            .header("Content-Type", "application/json");

        HttpRequest.BodyPublisher publisher = body != null
            ? HttpRequest.BodyPublishers.ofString(gson.toJson(body))
            : HttpRequest.BodyPublishers.noBody();
        builder.method(method, publisher);

        return send(builder.build(), method + " " + url);
    }

    private String agentRequest(String method, String path, Object body) {
        String url = config.v1Url() + path;
        var builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Authorization", "Bearer " + agentToken())
            .header("Content-Type", "application/json");

        HttpRequest.BodyPublisher publisher = body != null
            ? HttpRequest.BodyPublishers.ofString(gson.toJson(body))
            : HttpRequest.BodyPublishers.noBody();
        builder.method(method, publisher);

        return send(builder.build(), method + " " + url);
    }

    private String send(HttpRequest req, String label) {
        try {
            var res = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 400) {
                throw new AuthFIException("API error (" + label + "): " + res.body(), res.statusCode());
            }
            return res.body();
        } catch (AuthFIException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthFIException("API request failed (" + label + "): " + e.getMessage(), e);
        }
    }
}
