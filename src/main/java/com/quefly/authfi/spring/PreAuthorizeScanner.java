package com.quefly.authfi.spring;

import com.quefly.authfi.AuthFI;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.ClassUtils;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Walks every bean in the application context after startup, finds every {@code @PreAuthorize}
 * annotation, extracts permission/role literals from its SpEL expression, and syncs the
 * combined catalog to AuthFI via {@link AuthFI#permissions()}.
 *
 * <p>Result: the AuthFI console always knows the exact set of permissions the deployed code
 * enforces — devs never call {@code permissions().register(...)} manually.
 *
 * <p>Matches {@code hasAuthority('x')}, {@code hasAnyAuthority('x', 'y', ...)},
 * {@code hasRole('admin')}, and {@code hasAnyRole(...)} literal-arg invocations.
 * Dynamic / variable-based expressions are skipped (impossible to extract statically).
 */
public class PreAuthorizeScanner implements SmartInitializingSingleton {

    private static final Pattern AUTHORITY = Pattern.compile(
        "has(?:Any)?Authority\\s*\\(([^)]+)\\)");
    private static final Pattern ROLE = Pattern.compile(
        "has(?:Any)?Role\\s*\\(([^)]+)\\)");
    private static final Pattern STRING_LITERAL = Pattern.compile(
        "['\"]([^'\"]+)['\"]");

    private final AuthFI authfi;
    private final ApplicationContext context;

    public PreAuthorizeScanner(AuthFI authfi, ApplicationContext context) {
        this.authfi = authfi;
        this.context = context;
    }

    @Override
    public void afterSingletonsInstantiated() {
        Set<String> permissions = new HashSet<>();

        String[] beanNames = context.getBeanDefinitionNames();
        for (String name : beanNames) {
            Class<?> beanType;
            try {
                beanType = context.getType(name);
            } catch (Exception e) {
                continue;
            }
            if (beanType == null) continue;

            Class<?> userClass = ClassUtils.getUserClass(beanType);
            for (Method method : safeMethods(userClass)) {
                PreAuthorize pre = method.getAnnotation(PreAuthorize.class);
                if (pre == null) continue;
                extractInto(pre.value(), permissions);
            }
        }

        if (permissions.isEmpty()) return;
        for (String p : permissions) {
            authfi.permissions().register(p);
        }
        try {
            authfi.permissions().sync();
        } catch (Exception ignored) {
            // Sync failure shouldn't crash app startup — log + move on.
        }
    }

    private static Method[] safeMethods(Class<?> cls) {
        try {
            return cls.getDeclaredMethods();
        } catch (Throwable t) {
            return new Method[0];
        }
    }

    /** Extract {@code hasAuthority('x')} / {@code hasRole('y')} literals into the collector. */
    static void extractInto(String spel, Set<String> out) {
        if (spel == null || spel.isBlank()) return;
        consume(AUTHORITY.matcher(spel), out, "");
        consume(ROLE.matcher(spel), out, "");
    }

    private static void consume(Matcher m, Set<String> out, String prefix) {
        while (m.find()) {
            Matcher lits = STRING_LITERAL.matcher(m.group(1));
            while (lits.find()) {
                out.add(prefix + lits.group(1));
            }
        }
    }
}
