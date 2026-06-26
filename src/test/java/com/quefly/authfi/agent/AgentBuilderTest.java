package com.quefly.authfi.agent;

import com.quefly.authfi.AuthFI;
import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.AuthFIException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AgentBuilderTest {

    @Test
    void agentBuilderRequiresTenant() {
        assertThrows(IllegalArgumentException.class, () ->
            AuthFI.agent().agentId("agt_x").agentSecret("ags_y").build());
    }

    @Test
    void agentBuilderRequiresAgentId() {
        assertThrows(IllegalArgumentException.class, () ->
            AuthFI.agent().tenant("acme").agentSecret("ags_y").build());
    }

    @Test
    void agentBuilderRequiresAgentSecret() {
        assertThrows(IllegalArgumentException.class, () ->
            AuthFI.agent().tenant("acme").agentId("agt_x").build());
    }

    @Test
    void agentBuilderCreatesAgentModeInstance() {
        AuthFI agent = AuthFI.agent()
            .tenant("acme")
            .agentId("agt_abc123")
            .agentSecret("ags_xyz789")
            .build();

        assertEquals(AuthFIConfig.AuthMode.AGENT_CREDENTIALS, agent.getConfig().authMode());
        assertEquals("agt_abc123", agent.getConfig().agentId());
        assertEquals("ags_xyz789", agent.getConfig().agentSecret());
        assertNotNull(agent.agentAuth());
    }

    @Test
    void agentAuthRejectedInClientMode() {
        AuthFI customer = AuthFI.client()
            .tenant("acme")
            .apiKey("sk_test")
            .build();

        var ex = assertThrows(AuthFIException.class,
            () -> customer.agentAuth().token());
        assertEquals(400, ex.getStatus());
    }

    @Test
    void managementApiRejectedInAgentMode() {
        AuthFI agent = AuthFI.agent()
            .tenant("acme")
            .agentId("agt_x")
            .agentSecret("ags_y")
            .build();

        // users().list() goes through manageRequest which checks authMode
        var ex = assertThrows(AuthFIException.class,
            () -> agent.users().list());
        assertEquals(403, ex.getStatus());
    }

    @Test
    void agentConfigBuildsAgentTokenEndpoint() {
        AuthFI agent = AuthFI.agent()
            .tenant("acme")
            .agentId("agt_x")
            .agentSecret("ags_y")
            .baseUrl("https://api.authfi.io")
            .build();

        assertEquals("https://api.authfi.io/v1/acme/agents/token",
            agent.getConfig().agentTokenEndpoint());
    }
}
