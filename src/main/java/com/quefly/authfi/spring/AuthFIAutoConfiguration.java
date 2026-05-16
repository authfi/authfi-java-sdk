package com.quefly.authfi.spring;

import com.quefly.authfi.AuthFI;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Spring Boot auto-configuration for AuthFI.
 *
 * <p>Three usage modes auto-activate based on properties set under {@code authfi.*}:
 *
 * <ul>
 *   <li>Customer app + API key — {@code authfi.tenant} + {@code authfi.api-key}</li>
 *   <li>Customer app + service identity — {@code authfi.tenant} + {@code authfi.client-id} / {@code authfi.client-secret}</li>
 *   <li>Agent process — {@code authfi.tenant} + {@code authfi.agent.id} / {@code authfi.agent.secret}</li>
 * </ul>
 *
 * <p>If {@code spring-security-oauth2-resource-server} is on the classpath, an
 * {@link AuthFIJwtAuthenticationConverter} bean is auto-registered so
 * {@code @PreAuthorize("hasAuthority('read:users')")} works against AuthFI tokens.
 *
 * <p>If {@code authfi.permission-sync.enabled=true} (default), {@link PreAuthorizeScanner}
 * walks every controller's {@code @PreAuthorize} annotations on boot and syncs the
 * implied permission catalog to AuthFI.
 */
@Configuration
@ConditionalOnClass(AuthFI.class)
@ConditionalOnProperty(prefix = "authfi", name = "tenant")
@EnableConfigurationProperties(AuthFIProperties.class)
public class AuthFIAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AuthFI authfi(AuthFIProperties props) {
        // Agent mode wins if explicit agent creds are present.
        if (props.getAgent() != null
            && props.getAgent().getId() != null
            && props.getAgent().getSecret() != null) {
            return AuthFI.agent()
                .tenant(props.getTenant())
                .agentId(props.getAgent().getId())
                .agentSecret(props.getAgent().getSecret())
                .baseUrl(props.getBaseUrl())
                .build();
        }
        // Service identity (OAuth2 client_credentials)
        if (props.getClientId() != null && props.getClientSecret() != null) {
            return AuthFI.service()
                .tenant(props.getTenant())
                .clientId(props.getClientId())
                .clientSecret(props.getClientSecret())
                .baseUrl(props.getBaseUrl())
                .build();
        }
        // API key (default)
        return AuthFI.client()
            .tenant(props.getTenant())
            .apiKey(props.getApiKey())
            .baseUrl(props.getBaseUrl())
            .build();
    }

    /**
     * Inner configuration — activated only when Spring Security's JWT resource server is on classpath.
     * Adds the AuthFI claim-shape converter so {@code @PreAuthorize("hasAuthority('foo')")}
     * resolves against {@code permissions[]} / {@code roles[]} claims.
     */
    @Configuration
    @ConditionalOnClass(Jwt.class)
    public static class AuthFISecurityConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public Converter<Jwt, AbstractAuthenticationToken> authfiJwtAuthenticationConverter() {
            return new AuthFIJwtAuthenticationConverter();
        }
    }

    /**
     * Inner configuration — silent permission-catalog sync by scanning {@code @PreAuthorize}.
     * Skip by setting {@code authfi.permission-sync.enabled=false}.
     */
    @Configuration
    @ConditionalOnProperty(
        prefix = "authfi.permission-sync",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
    public static class AuthFIPermissionSyncConfiguration {

        @Bean
        @ConditionalOnClass(name = "org.springframework.security.access.prepost.PreAuthorize")
        @ConditionalOnMissingBean
        public PreAuthorizeScanner preAuthorizeScanner(AuthFI authfi, ApplicationContext context) {
            return new PreAuthorizeScanner(authfi, context);
        }
    }
}
