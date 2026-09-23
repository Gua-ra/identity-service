// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The short human fingerprint of a device authority key (ADM-009 decision 5, revision 4).
 *
 * <p>It is the only thing crossing between two phones that a person has to compare, so it is stated here
 * rather than left to whichever screen shows it. <b>Eight characters</b>, from the <b>31-character alphabet
 * {@code ABCDEFGHJKLMNPQRSTUVWXYZ2346789}</b>: the same alphabet the browser-approval code uses, with I, O,
 * 0, 1, 5 and S left out, because a fingerprint two people read aloud across a room fails at exactly the
 * characters that sound or look alike.
 *
 * <p><b>Derived, never issued.</b> Both devices compute the same eight characters from the same 32 public
 * bytes, so the comparison means the two phones are looking at one key. A server-issued nonce would mean
 * only that both had spoken to the same server, which is the property that is already assumed and not the
 * one being checked.
 *
 * <p>Eight characters of this alphabet carry just under 40 bits. That is not collision resistance and is not
 * meant to be: it defends a human comparison inside a live ceremony against a key swapped in the middle, and
 * the server separately refuses a grant over any key that is not a live candidate of that same account, so
 * an attacker has to find a near-collision against one specific key within the candidate's short life.
 */
public final class AuthorityFingerprint {

    /** No I, O, 0, 1, 5 or S. A fingerprint gets read aloud. */
    static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ2346789";

    /** Eight characters, shown in two groups of four. */
    public static final int LENGTH = 8;

    private static final String DOMAIN = "gua-authority-candidate.v1";

    private AuthorityFingerprint() {
    }

    /**
     * The fingerprint of one raw Ed25519 device key.
     *
     * <p>Domain-separated, so the same bytes used for something else never produce the same string, and taken
     * from the front of the digest rather than from the key itself: a fingerprint that showed key bytes would
     * make two keys with a shared prefix look identical.
     */
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
