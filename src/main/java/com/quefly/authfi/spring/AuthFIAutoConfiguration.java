package com.quefly.authfi.spring;

import com.quefly.authfi.AuthFI;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot auto-configuration for AuthFI.
 *
 * Add to application.yml:
 * <pre>
 * authfi:
 *   tenant: acme
 *   api-key: sk_live_...
 * </pre>
 *
 * Then inject AuthFI anywhere:
 * <pre>
 * &#64;Autowired AuthFI authfi;
 * </pre>
 */
@Configuration
@ConditionalOnClass(AuthFI.class)
@ConditionalOnProperty(prefix = "authfi", name = "tenant")
public class AuthFIAutoConfiguration {

    @Bean
    @ConfigurationProperties(prefix = "authfi")
    @ConditionalOnMissingBean
    public AuthFIProperties authfiProperties() {
        return new AuthFIProperties();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthFI authfi(AuthFIProperties props) {
        if (props.getClientId() != null && props.getClientSecret() != null) {
            return AuthFI.service()
                .tenant(props.getTenant())
                .clientId(props.getClientId())
                .clientSecret(props.getClientSecret())
                .baseUrl(props.getBaseUrl())
                .build();
        }
        return AuthFI.client()
            .tenant(props.getTenant())
            .apiKey(props.getApiKey())
            .baseUrl(props.getBaseUrl())
            .build();
    }
}
