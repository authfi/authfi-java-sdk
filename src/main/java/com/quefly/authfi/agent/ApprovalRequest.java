package com.quefly.authfi.agent;

/** The 202 response from POST /{tenant}/v1/agents/request-approval. */
public record ApprovalRequest(
    String approvalId,
    String status,
    long expiresAtEpochSec,
    String pollUrl
) {}
