package com.quefly.authfi.agent;

/**
 * Agent kind at registration time.
 *
 * <ul>
 *   <li>{@link #DELEGATED} — agent acts on behalf of the owning user. Token carries the owner's identity context.
 *   <li>{@link #AUTONOMOUS} — agent has its own identity. Token does not carry an owner.
 * </ul>
 */
public enum AgentType {
    DELEGATED("delegated"),
    AUTONOMOUS("autonomous");

    private final String wire;

    AgentType(String wire) {
        this.wire = wire;
    }

    /** Lowercase wire form used in JSON request bodies. */
    public String wireValue() {
        return wire;
    }
}
