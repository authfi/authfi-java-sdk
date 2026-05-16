package com.quefly.authfi.agent;

/**
 * Outcome of an AAP approval — sealed so callers handle every state via one switch.
 *
 * <pre>
 * switch (approval) {
 *     case Approval.Approved a -&gt; doIt();
 *     case Approval.Denied d   -&gt; log("denied: " + d.reason());
 *     case Approval.Expired e  -&gt; log("expired");
 *     case Approval.TimedOut t -&gt; log("client gave up");
 *     case Approval.Pending p  -&gt; log("still waiting");
 * }
 * </pre>
 */
public sealed interface Approval
    permits Approval.Pending, Approval.Approved, Approval.Denied, Approval.Expired, Approval.TimedOut {

    String approvalId();

    /** Server returned status=pending. */
    record Pending(String approvalId, long expiresAtEpochSec) implements Approval {}

    /** Server returned status=approved. */
    record Approved(String approvalId, String approverUserId, long approvedAtEpochSec) implements Approval {}

    /** Server returned status=denied. */
    record Denied(String approvalId, String reason, long deniedAtEpochSec) implements Approval {}

    /** Server returned status=expired (server-side timeout, NOT client-side). */
    record Expired(String approvalId) implements Approval {}

    /** Client-side timeout — caller's {@code awaitDecision} bound was hit before the server resolved. */
    record TimedOut(String approvalId) implements Approval {}
}
