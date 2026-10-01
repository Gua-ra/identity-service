package me.sarahlacerda.gua.identityservice.account.genesis;

import java.time.Instant;

/** Binds one accountId to one roster homeserver id. It carries no phone number, phone hash or Matrix user id. */
public record PlacementRecord(
        int version,
        int generation,
        AccountId accountId,
        byte origin,
        String homeserverId,
        Instant issuedAt,
        Instant notBefore,
        Instant notAfter,
        byte[] canonicalBytes) {

    /** Also the signature domain separator. */
    public static final String MAGIC = "GUAP";

    public static final int VERSION = 0x01;

    public static final int GENERATION_ONE = 0x01;

    /** Bytes before the variable-length homeserver id: magic, version, generation, accountId, origin, n. */
    public static final int FIXED_PREFIX_LENGTH = 42;

    /** Bytes after it: three 8-byte timestamps. */
    public static final int TRAILER_LENGTH = 24;

    public static final int LENGTH_WITHOUT_HOMESERVER_ID = FIXED_PREFIX_LENGTH + TRAILER_LENGTH;

    public static final int MAX_HOMESERVER_ID_LENGTH = 64;

    public boolean isGenesisRooted() {
        return origin == AccountId.CLASS_GENESIS;
    }

    @Override
    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }
}
