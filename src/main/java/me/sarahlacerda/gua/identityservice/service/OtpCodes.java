package me.sarahlacerda.gua.identityservice.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Comparison shared by every service that redeems a one-time code. */
public final class OtpCodes {

    private OtpCodes() {
    }

    /**
     * Whether {@code submitted} equals {@code stored} without leaking, through
     * timing, how many leading characters matched. A {@code null} submission is a
     * mismatch, never an error, so it counts as a wrong guess like any other.
     */
    public static boolean matches(String stored, String submitted) {
        byte[] expected = stored.getBytes(StandardCharsets.UTF_8);
        byte[] actual = submitted == null ? new byte[0] : submitted.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }
}
