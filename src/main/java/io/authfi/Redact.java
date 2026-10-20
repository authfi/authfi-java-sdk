package io.authfi;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Removes secrets from text that may be logged or put in an exception message.
 *
 * <p>Two layers: shapes that are secrets wherever they appear (a JWT, a PEM block, an AuthFI key
 * prefix, a bearer credential, a credential-named field), and the literal secret values a particular
 * client holds, in the plain, JSON-escaped and URL-encoded spellings a server may reflect them in.
 */
public final class Redact {

    public static final String MASK = "[redacted]";

    private static final String NAMES =
        "(?:client[_-]?secret|client[_-]?assertion|access[_-]?token|refresh[_-]?token|id[_-]?token"
            + "|x-api-key|api[_-]?key|agent[_-]?secret|private[_-]?key|password|secret)";

    // A header alone (as in "expected -----BEGIN PRIVATE KEY-----") is not a key; header plus a body is.
    private static final Pattern PEM = Pattern.compile(
        "-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\s|\\\\n|\\\\r)*(?:[A-Za-z0-9+/=\\s]|\\\\n|\\\\r){8,}"
            + "(-----END [A-Z ]*PRIVATE KEY-----)?");
    private static final Pattern JWT = Pattern.compile(
        "eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");
    private static final Pattern KEYS = Pattern.compile(
        "\\b(sk_(live|test)_|ags_|FIS-)[A-Za-z0-9_\\-]{6,}");
    private static final Pattern BEARER = Pattern.compile("(?i)\\b(bearer\\s+)[A-Za-z0-9._~+/-]{8,}=*");
    /** name = "value with spaces" (quotes plain or JSON-escaped). */
    private static final Pattern QUOTED = Pattern.compile(
        "(?i)(" + NAMES + "(?:\\\\?[\"'])?\\s*(?:[=:]|%3D|%3A)\\s*\\\\?[\"'])[^\"'\\\\]*");
    /** name=value, name: value, name%3Dvalue. */
    private static final Pattern PLAIN = Pattern.compile(
        "(?i)(" + NAMES + "(?:\\\\?[\"'])?\\s*(?:[=:]|%3D|%3A)\\s*)[^\"'&\\s,}\\\\]+");

    private Redact() {
    }

    /** Masks secret-shaped text. Null stays null. */
    public static String scrub(String text) {
        if (text == null || text.isEmpty()) return text;
        String out = PEM.matcher(text).replaceAll(MASK);
        out = JWT.matcher(out).replaceAll(MASK);
        out = KEYS.matcher(out).replaceAll(MASK);
        out = BEARER.matcher(out).replaceAll("$1" + MASK);
        out = QUOTED.matcher(out).replaceAll("$1" + MASK);
        return PLAIN.matcher(out).replaceAll("$1" + MASK);
    }

    /** Masks the given literal secret values, then secret-shaped text. */
    public static String scrub(String text, String... secrets) {
        if (text == null || text.isEmpty()) return text;
        String out = text;
        if (secrets != null) {
            for (String s : secrets) {
                if (s == null || s.length() < 4) continue;
                out = out.replace(s, MASK)
                    .replace(jsonEscaped(s), MASK)
                    .replace(URLEncoder.encode(s, StandardCharsets.UTF_8), MASK);
            }
        }
        return scrub(out);
    }

    private static String jsonEscaped(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
