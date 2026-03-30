package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

import java.util.Map;

/** Organization management API. */
public class OrgsClient {

    private final HttpTransport http;

    public OrgsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    /** Create an organization. */
    public String create(String name, String slug) {
        return http.post("/orgs", Map.of("name", name, "slug", slug));
    }

    /** Get org by ID. */
    public String get(String orgId) {
        return http.get("/orgs/" + orgId);
    }

    /** List organizations. */
    public String list() {
        return http.get("/orgs");
    }

    /** Update org. */
    public String update(String orgId, Map<String, Object> properties) {
        return http.patch("/orgs/" + orgId, properties);
    }

    /** Delete org. */
    public String delete(String orgId) {
        return http.delete("/orgs/" + orgId);
    }

    /** Add member to org. */
    public String addMember(String orgId, String userId, String role) {
        return http.post("/orgs/" + orgId + "/members", Map.of("user_id", userId, "role", role));
    }

    /** Remove member from org. */
    public String removeMember(String orgId, String userId) {
        return http.delete("/orgs/" + orgId + "/members/" + userId);
    }

    /** List members of an org. */
    public String listMembers(String orgId) {
        return http.get("/orgs/" + orgId + "/members");
    }

    /** Configure SSO for an org. */
    public String configureSso(String orgId, Map<String, Object> ssoConfig) {
        return http.put("/orgs/" + orgId + "/sso", ssoConfig);
    }

    /** Set org branding. */
    public String setBranding(String orgId, Map<String, Object> branding) {
        return http.put("/orgs/" + orgId + "/branding", branding);
    }
}
