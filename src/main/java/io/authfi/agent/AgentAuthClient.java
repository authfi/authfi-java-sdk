package io.authfi.agent;

import com.google.gson.Gson;
import io.authfi.AuthFIConfig;
import io.authfi.AuthFIException;
import io.authfi.HttpTransport;

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * The seamless agentic API. Only valid when the parent {@link io.authfi.AuthFI}
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

    /**
     * Submit a human-approval request at the deployment's advertised approval endpoint. Returns
     * immediately (HTTP 202). The request is signed with the agent's key; no secret is sent.
     */
    public ApprovalRequest requestApproval(String action, Map<String, Object> context) {
        requireAgentMode();
        Map<String, Object> resp = unwrap(http.requestApproval(action, context));
        String id = asString(resp.get("approval_id"));
        if (id == null || id.isBlank()) {
            throw new AuthFIException("The approval request was accepted but carried no approval id.", 502);
        }
        String status = asString(resp.get("status"));
        if (status == null || status.isBlank()) {
            throw new AuthFIException("The approval request was accepted but carried no status.", 502);
        }
        return new ApprovalRequest(id, status, epoch(resp.get("expires_at")),
            asString(resp.get("poll_url")));
    }

    /** A single poll of an approval, with the agent's token. Use {@link #awaitDecision} to block. */
    public Approval checkApproval(String approvalId) {
        requireAgentMode();
        return parseApproval(http.approvalStatus(approvalId), approvalId);
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

    /** The platform wraps every answer as {"data": {...}}; older shapes are read as they are. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> unwrap(String json) {
        Map<String, Object> r;
        try {
            r = gson.fromJson(json, Map.class);
        } catch (com.google.gson.JsonParseException e) {
            throw new AuthFIException("The approval answer was not a JSON object.", 502);
        }
        if (r == null) {
            throw new AuthFIException("The approval answer was empty.", 502);
        }
        return r.get("data") instanceof Map ? (Map<String, Object>) r.get("data") : r;
    }

    private static Object firstNonNull(Object a, Object b) {
        return a != null ? a : b;
    }

    /** Epoch seconds from either a number or an RFC 3339 timestamp; 0 when absent. */
    private static long epoch(Object o) {
        if (o instanceof Number n) return n.longValue();
        if (o instanceof String t && !t.isBlank()) {
            try {
                return java.time.Instant.parse(t).getEpochSecond();
            } catch (java.time.format.DateTimeParseException e) {
                return 0L;
            }
        }
        return 0L;
    }

    private Approval parseApproval(String json, String approvalId) {
        Map<String, Object> r = unwrap(json);
        String status = asString(r.get("status"));
        if (status == null) {
            throw new AuthFIException("The approval answer carried no status.", 502);
        }

        return switch (status) {
            case "approved" -> new Approval.Approved(approvalId,
                asString(r.get("approver_user_id")), epoch(firstNonNull(r.get("resolved_at"), r.get("approved_at"))));
            case "denied" -> new Approval.Denied(approvalId,
                asString(r.get("reason")), epoch(firstNonNull(r.get("resolved_at"), r.get("denied_at"))));
            case "expired" -> new Approval.Expired(approvalId);
            case "pending" -> new Approval.Pending(approvalId, epoch(r.get("expires_at")));
            default -> throw new AuthFIException("The approval has an unknown status: " + status, 502);
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
