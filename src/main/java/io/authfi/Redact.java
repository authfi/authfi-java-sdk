package io.authfi;

import java.util.regex.Pattern;

/**
 * Removes secrets from text that may be logged or put in an exception message.
 *
 * <p>Two layers: shapes that are secrets wherever they appear (a JWT, a PEM block, an AuthFI key
 * prefix, a credential-named field), and the literal secret values a particular client holds.
 */
public final class Redact {

    public static final String MASK = "[redacted]";

    // A header alone (as in "expected -----BEGIN PRIVATE KEY-----") is not a key; header plus a body is.
    private static final Pattern PEM = Pattern.compile(
        "-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\s|\\\\n|\\\\r)*(?:[A-Za-z0-9+/=\\s]|\\\\n|\\\\r){8,}(-----END [A-Z ]*PRIVATE KEY-----)?");
    private static final Pattern JWT = Pattern.compile(
        "eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");
    private static final Pattern KEYS = Pattern.compile(
        "\\b(sk_(live|test)_|ags_|FIS-)[A-Za-z0-9_\\-]{6,}");
    private static final Pattern FIELDS = Pattern.compile(
        "(?i)((client_secret|client_assertion|access_token|refresh_token|api_key|agent_secret|private_key)"
            + "[\"']?\\s*[=:]\\s*[\"']?)[^\"'&\\s,}]+");

    private Redact() {
    }

    /** Masks secret-shaped text. Null stays null. */
    public static String scrub(String text) {
        if (text == null || text.isEmpty()) return text;
        String out = PEM.matcher(text).replaceAll(MASK);
        out = JWT.matcher(out).replaceAll(MASK);
        out = KEYS.matcher(out).replaceAll(MASK);
        return FIELDS.matcher(out).replaceAll("$1" + MASK);
    }

    /** Masks the given literal secret values, then secret-shaped text. */
    public static String scrub(String text, String... secrets) {
        if (text == null || text.isEmpty()) return text;
        String out = text;
        if (secrets != null) {
            for (String s : secrets) {
                if (s != null && s.length() >= 4) out = out.replace(s, MASK);
            }
        }
        return scrub(out);
    }
}
