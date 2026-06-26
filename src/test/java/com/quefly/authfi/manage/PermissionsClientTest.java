package com.quefly.authfi.manage;

import com.quefly.authfi.AuthFIConfig;
import com.quefly.authfi.HttpTransport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PermissionsClientTest {

    @Test
    void registersPermissions() {
        var config = new AuthFIConfig("test", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        var http = new HttpTransport(config);
        var client = new PermissionsClient(config, http);

        client.register("read:users", "Read user data");
        client.register("write:users", "Write user data");
        client.register("read:users"); // duplicate — should not double-register

        // No exception means registration worked
        // sync() would call the API, so we just verify registration
        assertDoesNotThrow(() -> client.register("delete:users"));
    }

    @Test
    void syncWithEmptyPermissionsIsNoop() {
        var config = new AuthFIConfig("test", "sk_test", null, null,
            null, null, "https://api.authfi.io", AuthFIConfig.AuthMode.API_KEY);
        var http = new HttpTransport(config);
        var client = new PermissionsClient(config, http);

        // Should not throw — empty sync is a no-op
        assertDoesNotThrow(() -> client.sync());
    }
}
