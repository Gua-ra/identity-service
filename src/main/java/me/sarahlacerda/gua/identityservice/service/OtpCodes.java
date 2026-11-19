package me.sarahlacerda.gua.identityservice.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Comparison shared by every service that redeems a one-time code. */
public final class OtpCodes {

    private OtpCodes() {
    }

    /**
     * Constant-time comparison: does not leak through timing how many leading characters matched. A
     * {@code null} submission is a mismatch, never an error.
     */
    public static boolean matches(String stored, String submitted) {
        byte[] expected = stored.getBytes(StandardCharsets.UTF_8);
        byte[] actual = submitted == null ? new byte[0] : submitted.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }
}
