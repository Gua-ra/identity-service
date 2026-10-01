// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.springframework.util.StringUtils;

/** Accepts base64 of PKCS#8 DER, or base64 of the PEM file the issuer hands out. */
final class AuthorityPushKeys {

    private static final String PEM_BEGIN = "-----BEGIN";

    private AuthorityPushKeys() {
    }

    static PrivateKey load(String algorithm, String configured) {
        if (!StringUtils.hasText(configured)) {
            throw new IllegalArgumentException("no key is configured");
        }
        byte[] decoded = Base64.getDecoder().decode(configured.replaceAll("\\s", ""));
        byte[] der = looksLikePem(decoded) ? derFromPem(new String(decoded, java.nio.charset.StandardCharsets.US_ASCII)) : decoded;
        try {
            return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception ex) {
            throw new IllegalArgumentException("the configured " + algorithm + " key is not PKCS#8", ex);
        }
    }

    private static boolean looksLikePem(byte[] decoded) {
        if (decoded.length < PEM_BEGIN.length()) {
            return false;
        }
        return new String(decoded, 0, PEM_BEGIN.length(), java.nio.charset.StandardCharsets.US_ASCII).equals(PEM_BEGIN);
    }

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
