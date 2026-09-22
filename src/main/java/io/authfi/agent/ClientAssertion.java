package io.authfi.agent;

import io.authfi.AuthFIException;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

/**
 * RFC 7523 §2.2 {@code private_key_jwt} client authentication for an AAP agent.
 *
 * <p>The agent holds its own Ed25519 keypair and proves possession by signing a short assertion.
 * The private half never leaves the process and is never sent to AuthFI — which is the whole point,
 * and the difference between an agent credential and a bearer artifact the IETF agent-auth draft's
 * security considerations call an antipattern.
 *
 * <p><b>Why this exists rather than a client secret.</b> The platform's discovery document
 * ({@code /.well-known/agent-configuration}) advertises
 * {@code "token_endpoint_auth_methods_supported": ["private_key_jwt"]} and nothing else, and
 * registering an agent with a public JWK issues <em>no</em> client secret at all. An agent
 * registered the recommended way therefore cannot authenticate with a secret — the server picks the
 * credential from the agent's stored record, never from the request, so there is no downgrade a
 * caller can ask for and none an attacker can force either.
 *
 * <p>No JWT library is used deliberately: an EdDSA JWS over two base64url segments is a signature
 * and two string concatenations, and a dependency here would be a supply-chain surface on the one
 * code path that handles a private key.
 */
public final class ClientAssertion {

    /** The RFC 7523 §2.1 assertion type. The token endpoint requires it alongside the assertion. */
    public static final String TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * How long an assertion is valid. Short by intent: an assertion is a bearer credential for its
     * lifetime, so the window in which a captured one is worth anything is the window to minimise.
     * The server additionally refuses assertion auth outright when it has no replay cache, rather
     * than accepting replays and hoping.
     */
    private static final Duration LIFETIME = Duration.ofMinutes(5);

    private ClientAssertion() {
    }

    /**
     * Build and sign an assertion.
     *
     * @param agentId    the agent id ({@code agt_…}); becomes both {@code iss} and {@code sub},
     *                   because in client authentication the agent is both the issuer of the
     *                   assertion and the subject it speaks about
     * @param audience   the token endpoint URL. It is checked, and a mismatch is refused — an
     *                   assertion signed for one endpoint must not be replayable at another
     * @param keyId      the {@code kid} registered with the public JWK; it selects the verifying key
     * @param privateKey the agent's Ed25519 private key, PKCS#8 PEM ({@code BEGIN PRIVATE KEY})
     * @return the compact JWS
     */
    public static String build(String agentId, String audience, String keyId, String privateKey) {
        require(agentId, "agentId");
        require(audience, "audience");
        require(keyId, "keyId");
        require(privateKey, "privateKey");

        long now = System.currentTimeMillis() / 1000L;
        String header = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":" + jsonString(keyId) + "}";
        String payload = "{"
            + "\"iss\":" + jsonString(agentId)
            + ",\"sub\":" + jsonString(agentId)
            + ",\"aud\":" + jsonString(audience)
            // jti is the replay id. A fresh one per assertion is what lets the server refuse a
            // second use of the same credential.
            + ",\"jti\":" + jsonString(UUID.randomUUID().toString())
            + ",\"iat\":" + now
            + ",\"exp\":" + (now + LIFETIME.toSeconds())
            + "}";

        String signingInput = b64u(header.getBytes(StandardCharsets.UTF_8))
            + "." + b64u(payload.getBytes(StandardCharsets.UTF_8));

        return signingInput + "." + b64u(sign(signingInput, privateKey));
    }

    // === Internal ===

    private static byte[] sign(String signingInput, String privateKeyPem) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(parsePkcs8(privateKeyPem));
            sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return sig.sign();
        } catch (AuthFIException e) {
            throw e;
        } catch (Exception e) {
            // Ed25519 is a JDK 15+ built-in, so a failure here is the key, not the algorithm.
            throw new AuthFIException("Could not sign the client assertion with the agent key", e);
        }
    }

    /**
     * Parse a PKCS#8 PEM private key.
     *
     * <p>Only {@code BEGIN PRIVATE KEY} is accepted. A {@code BEGIN OPENSSH PRIVATE KEY} or an
     * {@code EC PRIVATE KEY} is rejected by name rather than failing later inside the JCA with an
     * error that reads like a platform fault.
     */
    private static PrivateKey parsePkcs8(String pem) {
        String trimmed = pem.trim();
        if (!trimmed.contains("BEGIN PRIVATE KEY")) {
            String hint = trimmed.startsWith("-----BEGIN")
                ? "it is a " + trimmed.lines().findFirst().orElse("PEM block").replace("-", "").trim()
                : "it is not PEM at all";
            throw new AuthFIException(
                "The agent key must be an Ed25519 private key in PKCS#8 PEM form "
                    + "(-----BEGIN PRIVATE KEY-----), but " + hint
                    + ". Generate one with: openssl genpkey -algorithm ed25519", 400);
        }
        String body = trimmed
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(body);
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new AuthFIException("The agent key is not a usable Ed25519 PKCS#8 private key", e);
        }
    }

    /** base64url, no padding — RFC 7515 §2. */
    private static String b64u(byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /**
     * Minimal JSON string escaping for the values that go into the assertion.
     *
     * <p>These are ids and URLs, but escaping them is not optional: a value carrying a quote would
     * otherwise produce a JWS whose payload is not the payload we meant to sign.
     */
    private static String jsonString(String s) {
        StringBuilder out = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new AuthFIException(name + " is required to build a client assertion", 400);
        }
    }
}
