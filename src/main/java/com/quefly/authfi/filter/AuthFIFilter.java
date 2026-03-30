package com.quefly.authfi.filter;

import com.quefly.authfi.AuthFI;
import com.quefly.authfi.AuthFIException;
import com.quefly.authfi.auth.AuthFIClaims;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Servlet filter for JWT verification. Works with any servlet container
 * (Tomcat, Jetty, Undertow) and any framework (Spring, Quarkus, plain servlet).
 *
 * <pre>
 * // Spring Boot
 * &#64;Bean
 * FilterRegistrationBean&lt;AuthFIFilter&gt; authFilter(AuthFI authfi) {
 *     var reg = new FilterRegistrationBean&lt;&gt;(new AuthFIFilter(authfi, "read:users"));
 *     reg.addUrlPatterns("/api/users/*");
 *     return reg;
 * }
 *
 * // Plain servlet
 * servletContext.addFilter("authfi", new AuthFIFilter(authfi))
 *     .addMappingForUrlPatterns(null, true, "/api/*");
 * </pre>
 */
public class AuthFIFilter implements Filter {

    public static final String CLAIMS_ATTRIBUTE = "com.quefly.authfi.claims";

    private final AuthFI authfi;
    private final String[] requiredPermissions;

    public AuthFIFilter(AuthFI authfi, String... requiredPermissions) {
        this.authfi = authfi;
        this.requiredPermissions = requiredPermissions;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // Skip preflight
        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String header = req.getHeader("Authorization");
            AuthFIClaims claims = authfi.auth().verifyHeader(header);

            if (requiredPermissions.length > 0) {
                authfi.auth().requirePermissions(claims, requiredPermissions);
            }

            // Store claims on request for downstream use
            req.setAttribute(CLAIMS_ATTRIBUTE, claims);
            chain.doFilter(request, response);

        } catch (AuthFIException e) {
            res.setStatus(e.getStatus());
            res.setContentType("application/json");
            res.getWriter().write("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    /** Extract claims from request (set by this filter). */
    public static AuthFIClaims getClaims(HttpServletRequest request) {
        return (AuthFIClaims) request.getAttribute(CLAIMS_ATTRIBUTE);
    }
}
