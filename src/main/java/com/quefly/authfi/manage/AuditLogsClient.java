package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;

/**
 * Tenant audit log search.
 * Backed by GET /manage/v1/{tenant}/logs. Service auth.
 */
public class AuditLogsClient {

    private final HttpTransport http;

    public AuditLogsClient(AuthFIConfig config, HttpTransport http) {
        this.http = http;
    }

    /** List recent audit logs with default paging (limit=50). */
    public String list() {
        return http.get("/logs");
    }

    /**
     * Paginated audit log listing.
     *
     * @param limit  page size (1..100, default 50)
     * @param offset row offset
     * @param sinceRfc3339 optional RFC3339 timestamp to filter forward from (may be null)
     */
    public String list(int limit, int offset, String sinceRfc3339) {
        StringBuilder qs = new StringBuilder("/logs?limit=").append(limit).append("&offset=").append(offset);
        if (sinceRfc3339 != null && !sinceRfc3339.isBlank()) {
            qs.append("&since=").append(java.net.URLEncoder.encode(sinceRfc3339, java.nio.charset.StandardCharsets.UTF_8));
        }
        return http.get(qs.toString());
    }
}
