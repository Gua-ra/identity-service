package me.sarahlacerda.gua.identityservice.account.genesis;

import java.time.Instant;

/**
 * A generation-1 placement record: one accountId bound to one roster homeserver id, signed by that
 * homeserver's roster membership key.
 *
 * <p>It carries no identifier, phone number, phone hash or Matrix user id, which is what makes it
 * publishable. {@code PlacementRecordCodecTest} fails if this record grows such a field.
 *
 * @param version       format version, {@value #VERSION}
 * @param generation    placement generation, {@value #GENERATION_ONE}
 * @param accountId     the account this record places
 * @param origin        {@link AccountId#CLASS_BOOTSTRAP} or {@link AccountId#CLASS_GENESIS}; must equal
 *                      the class byte inside the accountId itself
 * @param homeserverId  the roster entry id of the holding homeserver, never the Matrix domain
 * @param issuedAt      when the signer issued it
 * @param notBefore     start of the validity window
 * @param notAfter      end of the validity window
 * @param canonicalBytes the exact bytes the signature covers, kept verbatim so nothing re-encodes them
 */
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

    /** ASCII magic, and the signature domain separator. */
    public static final String MAGIC = "GUAP";

    public static final int VERSION = 0x01;

    /** The only generation issued or accepted. */
    public static final int GENERATION_ONE = 0x01;

    /** Bytes before the variable-length homeserver id: magic, version, generation, accountId, origin, n. */
    public static final int FIXED_PREFIX_LENGTH = 42;

    /** Bytes after it: three 8-byte timestamps. */
    public static final int TRAILER_LENGTH = 24;

    /** Total length of a record carrying an {@code n}-byte homeserver id. */
    public static final int LENGTH_WITHOUT_HOMESERVER_ID = FIXED_PREFIX_LENGTH + TRAILER_LENGTH;

    public static final int MAX_HOMESERVER_ID_LENGTH = 64;

    /** True when this record is rooted in a registered genesis rather than a bootstrap id. */
    public boolean isGenesisRooted() {
        return origin == AccountId.CLASS_GENESIS;
    }

    /** A defensive copy: callers must never be able to edit the bytes a signature covers. */
    @Override
    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }
}
