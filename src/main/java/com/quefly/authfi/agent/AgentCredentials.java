package com.quefly.authfi.agent;

/**
 * Credentials handed back from {@link AgentsClient#register}.
 * The {@link #clientSecret()} is shown ONCE and is the only secret material —
 * callers must persist it securely (env var, Vault, etc.). It cannot be retrieved later.
 */
public record AgentCredentials(
    String agentId,
    String clientSecret,
    String type,
    String ownerUserId,
    long createdAtEpochSec,
    String warning
) {}
