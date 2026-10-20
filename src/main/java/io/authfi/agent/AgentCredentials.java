package io.authfi.agent;

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
) {
    /** Never prints the secret: a logged registration result must not leak it. */
    @Override
    public String toString() {
        return "AgentCredentials[agentId=" + agentId + ", clientSecret=[redacted], type=" + type
            + ", ownerUserId=" + ownerUserId + ", createdAtEpochSec=" + createdAtEpochSec + "]";
    }
}
