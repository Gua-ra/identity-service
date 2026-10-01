// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** The magic doubles as the signature domain, so a record cannot be replayed as another type. */
public enum AuthorityRecordType {

    ADOPT_ROOT("GUAA", AuthorityRecord.ADOPT_ROOT_LENGTH),

    DEVICE_GRANT("GUAD", AuthorityRecord.DEVICE_GRANT_LENGTH),

    DEVICE_REVOKE("GUAX", AuthorityRecord.DEVICE_REVOKE_LENGTH),

    AUTHORITY_RECOVERY("GUAR", AuthorityRecord.AUTHORITY_RECOVERY_LENGTH),

    OPPOSE("GUAO", AuthorityRecord.OPPOSE_LENGTH);

    private final String magic;
    private final int length;

    AuthorityRecordType(String magic, int length) {
        this.magic = magic;
        this.length = length;
    }

    public String magic() {
        return magic;
    }

    public byte[] magicBytes() {
        return magic.getBytes(StandardCharsets.US_ASCII);
    }

    public int length() {
        return length;
    }

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
