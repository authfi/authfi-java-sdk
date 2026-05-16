package com.quefly.authfi.agent;

import com.google.gson.Gson;
import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.AuthFIException;
import com.quefly.authfi.HttpTransport;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * The seamless agentic API. Only valid when the parent {@link com.quefly.authfi.AuthFI}
 * was built via {@code AuthFI.agent()}.
 *
 * <p>What an agent author writes — no polling loops, no token plumbing:
 * <pre>
 * AuthFI agent = AuthFI.agent().fromEnv().build();
 *
 * if (!agent.agentAuth().can("send_email_external")) return;
 *
 * agent.agentAuth().guard("send_email_external", Map.of("to", boss), () -&gt; {
 *     smtp.send(boss, "Daily summary", body);
 *     return null;
 * });
 * </pre>
 */
public class AgentAuthClient {

    private static final Duration DEFAULT_WAIT = Duration.ofMinutes(5);
    private static final long INITIAL_POLL_MS = 200L;
    private static final long MAX_POLL_MS = 2_000L;

    private final AuthFIConfig config;
    private final HttpTransport http;
    private final Gson gson = new Gson();

    public AgentAuthClient(AuthFIConfig config, HttpTransport http) {
        this.config = config;
        this.http = http;
    }

    /** Fetch (or return cached) the agent's access token. SDK refreshes ~60s before expiry. */
    public String token() {
        requireAgentMode();
        return http.agentToken();
    }

    /** Capabilities granted to this agent — populated as a side effect of {@link #token()}. */
    public Set<String> capabilities() {
        requireAgentMode();
        return http.agentCapabilities();
    }

    /** True iff the agent's capabilities include {@code action}. */
    public boolean can(String action) {
        return capabilities().contains(action);
    }

    /** POST /v1/{tenant}/agents/request-approval — submit a HIL approval request. Returns immediately (HTTP 202). */
    public ApprovalRequest requestApproval(String action, Map<String, Object> context) {
        requireAgentMode();
        Map<String, Object> body = new HashMap<>();
        body.put("agent_id", config.agentId());
        body.put("client_secret", config.agentSecret());
        body.put("requesting_action", action);
        body.put("context", context != null ? context : Map.of());

        String jsonBody = http.postAsAgent("/agents/request-approval", body);
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = gson.fromJson(jsonBody, Map.class);
        Number expires = (Number) resp.get("expires_at");
        return new ApprovalRequest(
            asString(resp.get("approval_id")),
            asString(resp.get("status")),
            expires != null ? expires.longValue() : 0L,
            asString(resp.get("poll_url"))
        );
    }

    /** GET /v1/{tenant}/agents/approvals/{id} — single poll. Use {@link #awaitDecision} for blocking. */
    public Approval checkApproval(String approvalId) {
        // Unauthenticated GET — the approval_id is the bearer of capability.
        String json = http.getAnonymous(config.v1Url() + "/agents/approvals/" + approvalId);
        return parseApproval(json, approvalId);
    }

    /**
     * Block until the approval resolves, server-side expires, or the caller-supplied timeout hits.
     * Exponential backoff polling (200ms → 2s, capped) — no caller loops.
     */
    public Approval awaitDecision(String approvalId, Duration timeout) {
        Duration effective = timeout != null ? timeout : DEFAULT_WAIT;
        long deadline = System.nanoTime() + effective.toNanos();
        long sleepMs = INITIAL_POLL_MS;

        while (true) {
            Approval current = checkApproval(approvalId);
            if (!(current instanceof Approval.Pending)) return current;

            if (System.nanoTime() >= deadline) {
                return new Approval.TimedOut(approvalId);
            }
            try {
                Thread.sleep(Math.min(sleepMs, Math.max(0L, (deadline - System.nanoTime()) / 1_000_000L)));
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return new Approval.TimedOut(approvalId);
            }
            sleepMs = Math.min(sleepMs * 2, MAX_POLL_MS);
        }
    }

    /**
     * The whole agentic flow in one call: capability-check, request-approval-if-needed,
     * await decision, run {@code work} on approve, throw on deny/expire/timeout.
     *
     * <p>If the action is in {@link #capabilities()} and the server flags it as always-allowed,
     * the work runs without an approval round-trip.
     *
     * @return whatever {@code work.call()} returns
     * @throws ApprovalDeniedException on Denied / Expired / TimedOut
     * @throws AuthFIException         if the capability isn't granted at all
     */
    public <T> T guard(String action, Map<String, Object> context, Callable<T> work) throws Exception {
        if (!can(action)) {
            throw new AuthFIException("Agent capability not granted: " + action, 403, "capability_missing");
        }
        ApprovalRequest req = requestApproval(action, context);
        Approval decision = awaitDecision(req.approvalId(), DEFAULT_WAIT);

        if (decision instanceof Approval.Approved) {
            return work.call();
        }
        if (decision instanceof Approval.Denied d) {
            throw new ApprovalDeniedException(d);
        }
        if (decision instanceof Approval.Expired e) {
            throw new ApprovalDeniedException(e, "server-side expiration");
        }
        if (decision instanceof Approval.TimedOut t) {
            throw new ApprovalDeniedException(t, "client-side timeout");
        }
        // Pending — defensive; awaitDecision should never return Pending after the loop exits.
        throw new ApprovalDeniedException(decision, "unexpected still-pending after wait");
    }

    /** Convenience for void work — wraps a {@link Runnable}. */
    public void guard(String action, Map<String, Object> context, Runnable work) {
        try {
            guard(action, context, () -> { work.run(); return null; });
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // === Internal ===

    private void requireAgentMode() {
        if (config.authMode() != AuthFIConfig.AuthMode.AGENT_CREDENTIALS) {
            throw new AuthFIException(
                "agentAuth() requires AuthFI.agent() builder; current mode: " + config.authMode(),
                400);
        }
    }

    private Approval parseApproval(String json, String approvalId) {
        @SuppressWarnings("unchecked")
        Map<String, Object> r = gson.fromJson(json, Map.class);
        String status = asString(r.get("status"));
        if (status == null) status = "pending";

        return switch (status) {
            case "approved" -> {
                Number approvedAt = (Number) r.get("approved_at");
                yield new Approval.Approved(approvalId,
                    asString(r.get("approver_user_id")),
                    approvedAt != null ? approvedAt.longValue() : 0L);
            }
            case "denied" -> {
                Number deniedAt = (Number) r.get("denied_at");
                yield new Approval.Denied(approvalId,
                    asString(r.get("reason")),
                    deniedAt != null ? deniedAt.longValue() : 0L);
            }
            case "expired" -> new Approval.Expired(approvalId);
            default -> {
                Number expiresAt = (Number) r.get("expires_at");
                yield new Approval.Pending(approvalId,
                    expiresAt != null ? expiresAt.longValue() : 0L);
            }
        };
    }

    private static String asString(Object o) {
        return o != null ? o.toString() : null;
    }

    /** Thrown by {@link #guard} when the approval doesn't resolve favorably. */
    public static class ApprovalDeniedException extends RuntimeException {
        private final Approval approval;

        public ApprovalDeniedException(Approval approval) {
            super(describe(approval));
            this.approval = approval;
        }

        public ApprovalDeniedException(Approval approval, String detail) {
            super(describe(approval) + " (" + detail + ")");
            this.approval = approval;
        }

        public Approval getApproval() {
            return approval;
        }

        private static String describe(Approval a) {
            if (a instanceof Approval.Denied d) return "approval denied: " + d.reason();
            if (a instanceof Approval.Expired) return "approval expired server-side";
            if (a instanceof Approval.TimedOut) return "approval timed out client-side";
            if (a instanceof Approval.Pending) return "approval still pending";
            return "approved";
        }
    }
}
