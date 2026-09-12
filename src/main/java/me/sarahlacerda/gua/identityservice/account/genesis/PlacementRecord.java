// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.genesis;

import java.time.Instant;

/**
 * A generation-1 placement record: one accountId bound to one roster homeserver id, signed by that
 * homeserver's roster membership key (ADM-008 decision 7, ADM-001 L6 generation 1).
 *
 * <p><b>What it deliberately does not carry.</b> There is no identifier, no phone number, no phone hash
 * and no Matrix user id anywhere in this type or in the bytes {@link PlacementRecordCodec} produces.
 * That is ADM-001 L15 (routing-key privacy in replicated state) and L4, and it is the whole reason this
 * per-account object is publishable where the deleted {@code phone -> homeserver} directory write was
 * not: it binds nothing to an identifier. The accountId is a 256-bit hash, the origin byte is an audit
 * marker, the homeserver id is a roster id, and the three timestamps are a validity window. Adding a
 * field that identifies the human would reopen L15, so {@code PlacementRecordCodecTest} fails if this
 * record grows one.
 *
 * <p>The record is homeserver-asserted. Generation 1 is not the five-step transaction of L6, and it
 * improves no compromise condition (ADM-008 consequences); it records where an account already lives.
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

    /** ASCII magic, and the signature domain separator (ADM-008 decision 7). */
    public static final String MAGIC = "GUAP";

    public static final int VERSION = 0x01;

    /** The only generation this phase issues or accepts. */
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
