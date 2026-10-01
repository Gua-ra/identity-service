// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.time.Instant;
import java.util.HexFormat;

/** Published attestation of a settled chain head. It must carry no field that identifies a person. */
public record AuthorityHeadRecord(
        int version,
        int suite,
        byte[] accountReference,
        byte[] headHash,
        long headSeq,
        String homeserverId,
        Instant issuedAt,
        Instant notBefore,
        Instant notAfter,
        byte[] canonicalBytes) {

    /** Also the signature domain separator. */
    public static final String MAGIC = "GUAH";

    public static final String DOMAIN = "gua-account-authority-head.v1";

    public static final String LEAF_TYPE = "ACCOUNT_AUTHORITY";

    public static final int VERSION = 0x01;

    public static final int FIXED_PREFIX_LENGTH = 81;

    public static final int TRAILER_LENGTH = 24;

    public static final int LENGTH_WITHOUT_HOMESERVER_ID = FIXED_PREFIX_LENGTH + TRAILER_LENGTH;

    public static final int MAX_HOMESERVER_ID_LENGTH = 64;

    public String payloadHashHex() {
        return HexFormat.of().formatHex(AuthorityRecord.sha256(canonicalBytes));
    }

    public String headHashHex() {
        return HexFormat.of().formatHex(headHash);
    }

    @Override
    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }

    @Override
    public byte[] accountReference() {
        return accountReference.clone();
    }

    @Override
    public byte[] headHash() {
        return headHash.clone();
    }

    @Override
    public String toString() {
        return MAGIC + "#" + headSeq + "@" + homeserverId;
    }
}
