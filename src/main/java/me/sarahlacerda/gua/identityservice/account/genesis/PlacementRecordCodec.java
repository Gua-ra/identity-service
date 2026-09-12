// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

/**
 * The canonical codec for a generation-1 placement record (ADM-008 encoding tables).
 *
 * <pre>
 * off     len   field
 * 0       4     magic "GUAP"            also the signature domain
 * 4       1     version 0x01
 * 5       1     generation 0x01
 * 6       34    accountId raw           0x01 || class || SHA-256(genesis bytes)
 * 40      1     origin                  0x00 bootstrap | 0x01 genesis; equals the class byte at offset 7
 * 41      1     n                       len(homeserverId), 1..64
 * 42      n     homeserverId            ASCII roster id, never the Matrix domain
 * 42+n    8     issuedAt                epoch milliseconds, unsigned
 * 50+n    8     notBefore               epoch milliseconds, unsigned
 * 58+n    8     notAfter                epoch milliseconds, unsigned
 * 66+n          end
 * </pre>
 *
 * <p>Fixed layout with a single one-byte length prefix on the one variable field, big-endian, no
 * delimiters: the same two ADM-001 L4 rules the genesis objects obey, for the same reason. The decoder
 * refuses an unknown version or generation, a wrong length, a length prefix that does not agree with the
 * buffer, a non-printable or over-long homeserver id, an origin byte that disagrees with the class byte
 * inside the accountId, and a window that is inverted or longer than the 400 days ADM-008 decision 7
 * fixes. Bytes are kept verbatim on the decoded object so a verifier checks the signature against what
 * arrived rather than against a re-encoding.
 *
 * <p>There is no identifier, phone, phone hash or Matrix user id in this layout, and no room for one:
 * every offset is accounted for above. See {@link PlacementRecord} for why that is load-bearing.
 */
public final class PlacementRecordCodec {

    private static final byte[] MAGIC = PlacementRecord.MAGIC.getBytes(StandardCharsets.US_ASCII);

    private static final int OFFSET_VERSION = 4;
    private static final int OFFSET_GENERATION = 5;
    private static final int OFFSET_ACCOUNT_ID = 6;
    private static final int OFFSET_ORIGIN = 40;
    private static final int OFFSET_HOMESERVER_LENGTH = 41;
    private static final int OFFSET_HOMESERVER_ID = 42;

    /** ADM-008 decision 7: validity is 400 days. A longer window is refused, not clamped. */
    public static final Duration MAX_VALIDITY = Duration.ofDays(400);

    private PlacementRecordCodec() {
    }

    /**
     * Strictly decodes canonical bytes.
     *
     * @throws InvalidGenesisException on any rule above; the reason is a stable machine-readable token
     */
    public static PlacementRecord decode(byte[] bytes) {
        if (bytes == null || bytes.length < PlacementRecord.LENGTH_WITHOUT_HOMESERVER_ID + 1) {
            throw new InvalidGenesisException("wrong_length", "placement record is shorter than the fixed layout");
        }
        if (!MessageDigest.isEqual(Arrays.copyOfRange(bytes, 0, MAGIC.length), MAGIC)) {
            throw new InvalidGenesisException("bad_magic", "placement record magic is not " + PlacementRecord.MAGIC);
        }
        int version = bytes[OFFSET_VERSION] & 0xFF;
        if (version != PlacementRecord.VERSION) {
            throw new InvalidGenesisException("unknown_version", "unknown placement record version");
        }
        int generation = bytes[OFFSET_GENERATION] & 0xFF;
        if (generation != PlacementRecord.GENERATION_ONE) {
            throw new InvalidGenesisException("unknown_generation", "unknown placement generation");
        }

        byte[] rawAccountId = Arrays.copyOfRange(bytes, OFFSET_ACCOUNT_ID, OFFSET_ORIGIN);
        // Re-encoding the raw bytes and parsing the string applies the canonical-spelling rule in one
        // place rather than duplicating it here.
        AccountId accountId = AccountId.parse(AccountId.PREFIX + Base32.encode(rawAccountId));

        byte origin = bytes[OFFSET_ORIGIN];
        if (origin != accountId.rootClass()) {
            // The record's audit marker and the one baked into the id must agree, or a bootstrap
            // account could be published as a rooted one (ADM-001 L5's third audit marker).
            throw new InvalidGenesisException("origin_class_mismatch",
                    "the origin byte disagrees with the accountId root class");
        }

        int homeserverIdLength = bytes[OFFSET_HOMESERVER_LENGTH] & 0xFF;
        if (homeserverIdLength < 1 || homeserverIdLength > PlacementRecord.MAX_HOMESERVER_ID_LENGTH) {
            throw new InvalidGenesisException("bad_homeserver_id_length", "homeserver id length is out of range");
        }
        int expectedLength = PlacementRecord.LENGTH_WITHOUT_HOMESERVER_ID + homeserverIdLength;
        if (bytes.length != expectedLength) {
            // The length prefix and the buffer must agree exactly; trailing bytes would give one record
            // several spellings, and a signature over the longer buffer would still verify.
            throw new InvalidGenesisException("wrong_length",
                    "placement record length does not match its homeserver id length prefix");
        }

        byte[] homeserverIdBytes = Arrays.copyOfRange(bytes, OFFSET_HOMESERVER_ID,
                OFFSET_HOMESERVER_ID + homeserverIdLength);
        String homeserverId = decodeHomeserverId(homeserverIdBytes);

        int trailer = OFFSET_HOMESERVER_ID + homeserverIdLength;
        long issuedAt = readUnsignedLong(bytes, trailer, "issued_at");
        long notBefore = readUnsignedLong(bytes, trailer + 8, "not_before");
        long notAfter = readUnsignedLong(bytes, trailer + 16, "not_after");

        if (notAfter <= notBefore) {
            throw new InvalidGenesisException("inverted_window", "notAfter must be after notBefore");
        }
        if (notAfter - notBefore > MAX_VALIDITY.toMillis()) {
            throw new InvalidGenesisException("window_too_long",
                    "the validity window is longer than " + MAX_VALIDITY.toDays() + " days");
        }

        return new PlacementRecord(version, generation, accountId, origin, homeserverId,
                Instant.ofEpochMilli(issuedAt), Instant.ofEpochMilli(notBefore), Instant.ofEpochMilli(notAfter),
                bytes.clone());
    }

    /** Builds canonical bytes. The signature is produced over exactly what this returns. */
    public static byte[] encode(AccountId accountId, byte origin, String homeserverId, Instant issuedAt,
            Instant notBefore, Instant notAfter) {
        if (origin != accountId.rootClass()) {
            throw new IllegalArgumentException("the origin byte must equal the accountId root class");
        }
        byte[] homeserverIdBytes = homeserverId == null
                ? new byte[0]
                : homeserverId.getBytes(StandardCharsets.US_ASCII);
        if (homeserverIdBytes.length < 1 || homeserverIdBytes.length > PlacementRecord.MAX_HOMESERVER_ID_LENGTH) {
            throw new IllegalArgumentException("homeserver id must be 1 to "
                    + PlacementRecord.MAX_HOMESERVER_ID_LENGTH + " bytes");
        }
        // Round-trips through the same check the decoder applies, so an id this service cannot read back
        // is refused at signing time rather than by the far end.
        decodeHomeserverId(homeserverIdBytes);
        if (!notAfter.isAfter(notBefore)) {
            throw new IllegalArgumentException("notAfter must be after notBefore");
        }
        if (Duration.between(notBefore, notAfter).compareTo(MAX_VALIDITY) > 0) {
            throw new IllegalArgumentException("the validity window is longer than " + MAX_VALIDITY.toDays()
                    + " days");
        }

        byte[] out = new byte[PlacementRecord.LENGTH_WITHOUT_HOMESERVER_ID + homeserverIdBytes.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[OFFSET_VERSION] = (byte) PlacementRecord.VERSION;
        out[OFFSET_GENERATION] = (byte) PlacementRecord.GENERATION_ONE;
        System.arraycopy(accountId.rawBytes(), 0, out, OFFSET_ACCOUNT_ID, AccountId.RAW_LENGTH);
        out[OFFSET_ORIGIN] = origin;
        out[OFFSET_HOMESERVER_LENGTH] = (byte) homeserverIdBytes.length;
        System.arraycopy(homeserverIdBytes, 0, out, OFFSET_HOMESERVER_ID, homeserverIdBytes.length);

        int trailer = OFFSET_HOMESERVER_ID + homeserverIdBytes.length;
        writeUnsignedLong(out, trailer, issuedAt.toEpochMilli());
        writeUnsignedLong(out, trailer + 8, notBefore.toEpochMilli());
        writeUnsignedLong(out, trailer + 16, notAfter.toEpochMilli());
        return out;
    }

    /**
     * ASCII, printable, no whitespace. A roster id is an opaque token; refusing everything else keeps a
     * control character or a smuggled newline out of the one free-form field.
     */
    private static String decodeHomeserverId(byte[] value) {
        for (byte b : value) {
            int c = b & 0xFF;
            if (c <= 0x20 || c >= 0x7F) {
                throw new InvalidGenesisException("bad_homeserver_id",
                        "homeserver id has a byte outside printable ASCII");
            }
        }
        return new String(value, StandardCharsets.US_ASCII);
    }

    private static long readUnsignedLong(byte[] bytes, int offset, String field) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (bytes[offset + i] & 0xFFL);
        }
        if (value < 0) {
            // Epoch milliseconds are unsigned on the wire; a value with the top bit set is not a time
            // this service can represent, and must not wrap into a negative Instant.
            throw new InvalidGenesisException("timestamp_out_of_range", field + " is out of range");
        }
        return value;
    }

    private static void writeUnsignedLong(byte[] out, int offset, long value) {
        if (value < 0) {
            throw new IllegalArgumentException("timestamps are unsigned epoch milliseconds");
        }
        for (int i = 0; i < 8; i++) {
            out[offset + i] = (byte) (value >>> (56 - 8 * i));
        }
    }
}
