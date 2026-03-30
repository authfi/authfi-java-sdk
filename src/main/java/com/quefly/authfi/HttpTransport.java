package com.quefly.authfi;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/** HTTP client for AuthFI API calls. */
public class HttpTransport {

    private final AuthFIConfig config;
    private final HttpClient client;
    private final Gson gson = new Gson();

    // Cached service token
    private volatile String cachedToken;
    private volatile long tokenExpiry;

    public HttpTransport(AuthFIConfig config) {
        this.config = config;
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    /** GET request to management API. */
    public String get(String path) {
        return request("GET", path, null);
    }

    /** POST request to management API. */
    public String post(String path, Object body) {
        return request("POST", path, body);
    }

    /** PUT request to management API. */
    public String put(String path, Object body) {
        return request("PUT", path, body);
    }

    /** DELETE request to management API. */
    public String delete(String path) {
        return request("DELETE", path, null);
    }

    /** PATCH request to management API. */
    public String patch(String path, Object body) {
        return request("PATCH", path, body);
    }

    /** OAuth2 client_credentials token. */
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

    /** OAuth2 token exchange (on-behalf-of). */
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

    // --- Internal ---

    private String request(String method, String path, Object body) {
        String url = config.manageUrl() + path;
        var builder = HttpRequest.newBuilder().uri(URI.create(url));

        // Auth header
        if (config.authMode() == AuthFIConfig.AuthMode.API_KEY) {
            builder.header("X-API-Key", config.apiKey());
        } else {
            builder.header("Authorization", "Bearer " + clientCredentialsToken());
        }

        builder.header("Content-Type", "application/json");

        HttpRequest.BodyPublisher bodyPublisher = body != null
            ? HttpRequest.BodyPublishers.ofString(gson.toJson(body))
            : HttpRequest.BodyPublishers.noBody();

        builder.method(method, bodyPublisher);

        try {
            var res = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 400) {
                throw new AuthFIException("API error: " + res.body(), res.statusCode());
            }
            return res.body();
        } catch (AuthFIException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthFIException("API request failed: " + e.getMessage(), e);
        }
    }
}
