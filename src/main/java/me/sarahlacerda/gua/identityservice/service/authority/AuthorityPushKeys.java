// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.springframework.util.StringUtils;

/**
 * Loads the two push signing keys out of configuration, in either shape an operator will actually have.
 *
 * <h2>Why this is not two lines at each call site</h2>
 *
 * <p>It was, and both were wrong in the same way. Each transport base64-decoded its configured value and
 * handed the bytes straight to {@link PKCS8EncodedKeySpec}, which is right only when the value is base64 of
 * PKCS#8 <em>DER</em>. What an operator holds is neither: Apple issues a {@code .p8} and Google puts
 * {@code private_key} in the service-account JSON, and both are PEM. Base64 a PEM file and the bytes that
 * come back begin {@code -----BEGIN PRIVATE KEY-----}, which is not a key, and the failure surfaces at the
 * first alert rather than at startup: the transport counts as configured, ADM-009 gate 2 lets the deployment
 * start, and the first pending transition is announced to nobody. That is exactly the state the gate exists
 * to forbid, so both shapes are accepted here and the result is checked at startup.
 */
final class AuthorityPushKeys {

    private static final String PEM_BEGIN = "-----BEGIN";

    private AuthorityPushKeys() {
    }

    /**
     * @param algorithm {@code EC} for the Apple key, {@code RSA} for the Google one.
     * @param configured base64 of PKCS#8 DER, or base64 of the PEM document the issuer handed over.
     */
    static PrivateKey load(String algorithm, String configured) {
        if (!StringUtils.hasText(configured)) {
            throw new IllegalArgumentException("no key is configured");
        }
        byte[] decoded = Base64.getDecoder().decode(configured.replaceAll("\\s", ""));
        byte[] der = looksLikePem(decoded) ? derFromPem(new String(decoded, java.nio.charset.StandardCharsets.US_ASCII)) : decoded;
        try {
            return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception ex) {
            // The message names the algorithm and nothing else: the key material never reaches a log line.
            throw new IllegalArgumentException("the configured " + algorithm + " key is not PKCS#8", ex);
        }
    }

    private static boolean looksLikePem(byte[] decoded) {
        if (decoded.length < PEM_BEGIN.length()) {
            return false;
        }
        return new String(decoded, 0, PEM_BEGIN.length(), java.nio.charset.StandardCharsets.US_ASCII).equals(PEM_BEGIN);
    }

    /** The body between the armour lines, which is the DER this needs. */
    private static byte[] derFromPem(String pem) {
        StringBuilder body = new StringBuilder();
        for (String line : pem.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("-----")) {
                continue;
            }
            body.append(trimmed);
        }
        if (body.isEmpty()) {
            throw new IllegalArgumentException("the configured key is PEM armour with no body");
        }
        return Base64.getDecoder().decode(body.toString());
    }
}
