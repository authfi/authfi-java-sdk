package com.quefly.authfi.spring;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Maps AuthFI JWT claims into Spring Security {@code GrantedAuthority}s so the standard
 * {@code @PreAuthorize("hasAuthority('read:users')")} expression works verbatim.
 *
 * <ul>
 *   <li>{@code permissions[]} claim → authority per item, NO prefix (so {@code hasAuthority('read:users')} matches).
 *   <li>{@code roles[]} claim → authority per item with {@code ROLE_} prefix (so {@code hasRole('admin')} matches).
 * </ul>
 *
 * Wire into Spring Security via {@link AuthFIAutoConfiguration} (automatic when this class is on the classpath
 * alongside {@code spring-security-oauth2-resource-server}) or manually:
 *
 * <pre>
 * &#64;Bean
 * SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
 *     http.oauth2ResourceServer(rs -&gt; rs.jwt(jwt -&gt;
 *         jwt.jwtAuthenticationConverter(new AuthFIJwtAuthenticationConverter())));
 *     return http.build();
 * }
 * </pre>
 */
public class AuthFIJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        for (String p : strList(jwt, "permissions")) {
            authorities.add(new SimpleGrantedAuthority(p));
        }
        for (String r : strList(jwt, "roles")) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + r));
        }

        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }

    @SuppressWarnings("unchecked")
    private static List<String> strList(Jwt jwt, String claim) {
        Object value = jwt.getClaim(claim);
        if (value instanceof List<?> list) {
            List<String> out = new ArrayList<>(list.size());
            for (Object o : list) {
                if (o != null) out.add(o.toString());
            }
            return out;
        }
        return Collections.emptyList();
    }
}
