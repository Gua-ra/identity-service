// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Derived from the key bytes, never issued by the server, so a match proves both devices hold the same key. */
public final class AuthorityFingerprint {

    static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ2346789";

    public static final int LENGTH = 8;

    private static final String DOMAIN = "gua-authority-candidate.v1";

    private AuthorityFingerprint() {
    }

    public static String of(byte[] rawDeviceKey) {
        if (rawDeviceKey == null || rawDeviceKey.length != AuthorityRecord.KEY_LENGTH) {
            throw new IllegalArgumentException("a device key is " + AuthorityRecord.KEY_LENGTH + " bytes");
        }
        byte[] digest = sha256(DOMAIN.getBytes(java.nio.charset.StandardCharsets.US_ASCII), rawDeviceKey);
        StringBuilder out = new StringBuilder(LENGTH);
        for (int i = 0; i < LENGTH; i++) {
            out.append(ALPHABET.charAt((digest[i] & 0xFF) % ALPHABET.length()));
        }
        return out.toString();
    }

    private static byte[] sha256(byte[] domain, byte[] value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(domain);
            digest.update(value);
            return digest.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", ex);
        }
    }
}
