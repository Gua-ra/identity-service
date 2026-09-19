// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * The four record types of the authority chain (ADM-009 decision 2), each with its magic and its total
 * length.
 *
 * <p>The magic is the signature domain, which is why it is four ASCII bytes at offset 0 of the hashed
 * canonical bytes rather than a field beside them: no record can be replayed as another type, because a
 * verifier for one type never reaches the preimage of another.
 */
public enum AuthorityRecordType {

    /** Roots a bootstrap account. Signed by the device key it carries. */
    ADOPT_ROOT("GUAA", AuthorityRecord.ADOPT_ROOT_LENGTH),

    /** Activates another device key. Signed by an active, unquarantined device. */
    DEVICE_GRANT("GUAD", AuthorityRecord.DEVICE_GRANT_LENGTH),

    /** Deactivates a device key. Signed by an active device. */
    DEVICE_REVOKE("GUAX", AuthorityRecord.DEVICE_REVOKE_LENGTH),

    /** Replaces the device set with one device and installs a new recovery authority key. */
    AUTHORITY_RECOVERY("GUAR", AuthorityRecord.AUTHORITY_RECOVERY_LENGTH);

    private final String magic;
    private final int length;

    AuthorityRecordType(String magic, int length) {
        this.magic = magic;
        this.length = length;
    }

    /** The four ASCII magic bytes, which are also the signature domain. */
    public String magic() {
        return magic;
    }

    /** The ASCII magic bytes. */
    public byte[] magicBytes() {
        return magic.getBytes(StandardCharsets.US_ASCII);
    }

    /** Total canonical length, envelope and body together. */
    public int length() {
        return length;
    }

    /**
     * The type whose magic opens these bytes.
     *
     * @throws InvalidAuthorityRecordException {@code bad_magic} when no type claims them, which is also
     *                                        how a genesis object or a placement record is refused here
     */
    static AuthorityRecordType ofMagic(byte[] bytes) {
        if (bytes == null || bytes.length < AuthorityRecord.MAGIC_LENGTH) {
            throw new InvalidAuthorityRecordException("wrong_length", "an authority record is longer than this");
        }
        byte[] magicBytes = Arrays.copyOfRange(bytes, 0, AuthorityRecord.MAGIC_LENGTH);
        for (AuthorityRecordType candidate : values()) {
            if (MessageDigest.isEqual(magicBytes, candidate.magicBytes())) {
                return candidate;
            }
        }
        throw new InvalidAuthorityRecordException("bad_magic", "unknown authority record magic");
    }
}
