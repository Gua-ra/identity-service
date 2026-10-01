// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

/**
 * Canonical fixed-width encoding. Signatures and the published payload hash cover these exact bytes.
 *
 * <pre>
 * off     len   field
 * 0       4     magic "GUAH"            also the signature domain
 * 4       1     version 0x01
 * 5       1     suite 0x01              Ed25519 with SHA-256
 * 6       34    accountReference        exactly the 34 bytes the chain envelope carries at offset 6
 * 40      32    headHash                SHA-256 over the head record's canonical bytes
 * 72      8     headSeq                 unsigned, 1 or more
 * 80      1     n                       len(homeserverId), 1..64
 * 81      n     homeserverId            ASCII roster id, never the Matrix domain
 * 81+n    8     issuedAt                epoch milliseconds, unsigned
 * 89+n    8     notBefore               epoch milliseconds, unsigned
 * 97+n    8     notAfter                epoch milliseconds, unsigned
 * 105+n         end
 * </pre>
 */
public final class AuthorityHeadRecordCodec {

    private static final byte[] MAGIC = AuthorityHeadRecord.MAGIC.getBytes(StandardCharsets.US_ASCII);

    private static final int OFFSET_VERSION = 4;
    private static final int OFFSET_SUITE = 5;
    private static final int OFFSET_REFERENCE = 6;
    private static final int OFFSET_HEAD_HASH = 40;
    private static final int OFFSET_HEAD_SEQ = 72;
    private static final int OFFSET_HOMESERVER_LENGTH = 80;
    private static final int OFFSET_HOMESERVER_ID = 81;

    public static final Duration MAX_VALIDITY = Duration.ofDays(400);

    private AuthorityHeadRecordCodec() {
    }

    public static AuthorityHeadRecord decode(byte[] bytes) {
        if (bytes == null || bytes.length < AuthorityHeadRecord.LENGTH_WITHOUT_HOMESERVER_ID + 1) {
            throw new InvalidAuthorityRecordException("wrong_length",
                    "an authority head is shorter than the fixed layout");
        }
        if (!MessageDigest.isEqual(Arrays.copyOfRange(bytes, 0, MAGIC.length), MAGIC)) {
            throw new InvalidAuthorityRecordException("bad_magic",
                    "authority head magic is not " + AuthorityHeadRecord.MAGIC);
        }
        int version = bytes[OFFSET_VERSION] & 0xFF;
        if (version != AuthorityHeadRecord.VERSION) {
            throw new InvalidAuthorityRecordException("unknown_version", "unknown authority head version");
        }
        int suite = bytes[OFFSET_SUITE] & 0xFF;
        if (suite != AuthorityRecord.SUITE_ED25519_SHA256) {
            throw new InvalidAuthorityRecordException("unknown_suite", "unknown authority head suite");
        }

        byte[] reference = Arrays.copyOfRange(bytes, OFFSET_REFERENCE, OFFSET_HEAD_HASH);
        byte[] headHash = Arrays.copyOfRange(bytes, OFFSET_HEAD_HASH, OFFSET_HEAD_SEQ);
        if (isAllZero(headHash)) {
            throw new InvalidAuthorityRecordException("empty_head_hash",
                    "an authority head may not carry the all-zero head hash of an empty chain");
        }

        long headSeq = readUnsignedLong(bytes, OFFSET_HEAD_SEQ, "head_seq_out_of_range", "head_seq");
        if (headSeq < 1) {
            throw new InvalidAuthorityRecordException("head_seq_out_of_range",
                    "an authority head must name a record at position 1 or later");
        }

        int homeserverIdLength = bytes[OFFSET_HOMESERVER_LENGTH] & 0xFF;
        if (homeserverIdLength < 1 || homeserverIdLength > AuthorityHeadRecord.MAX_HOMESERVER_ID_LENGTH) {
            throw new InvalidAuthorityRecordException("bad_homeserver_id_length",
                    "homeserver id length is out of range");
        }
        int expectedLength = AuthorityHeadRecord.LENGTH_WITHOUT_HOMESERVER_ID + homeserverIdLength;
        if (bytes.length != expectedLength) {
            throw new InvalidAuthorityRecordException("wrong_length",
                    "authority head length does not match its homeserver id length prefix");
        }

        byte[] homeserverIdBytes = Arrays.copyOfRange(bytes, OFFSET_HOMESERVER_ID,
                OFFSET_HOMESERVER_ID + homeserverIdLength);
        String homeserverId = decodeHomeserverId(homeserverIdBytes);

        int trailer = OFFSET_HOMESERVER_ID + homeserverIdLength;
        long issuedAt = readUnsignedLong(bytes, trailer, "timestamp_out_of_range", "issued_at");
        long notBefore = readUnsignedLong(bytes, trailer + 8, "timestamp_out_of_range", "not_before");
        long notAfter = readUnsignedLong(bytes, trailer + 16, "timestamp_out_of_range", "not_after");

        if (notAfter <= notBefore) {
            throw new InvalidAuthorityRecordException("inverted_window", "notAfter must be after notBefore");
        }
        if (notAfter - notBefore > MAX_VALIDITY.toMillis()) {
            throw new InvalidAuthorityRecordException("window_too_long",
                    "the validity window is longer than " + MAX_VALIDITY.toDays() + " days");
        }

        return new AuthorityHeadRecord(version, suite, reference, headHash, headSeq, homeserverId,
                Instant.ofEpochMilli(issuedAt), Instant.ofEpochMilli(notBefore), Instant.ofEpochMilli(notAfter),
                bytes.clone());
    }

    public static byte[] encode(byte[] accountReference, byte[] headHash, long headSeq, String homeserverId,
            Instant issuedAt, Instant notBefore, Instant notAfter) {
        if (accountReference == null || accountReference.length != AuthorityRecord.ACCOUNT_REFERENCE_LENGTH) {
            throw new IllegalArgumentException("the account reference must be exactly "
                    + AuthorityRecord.ACCOUNT_REFERENCE_LENGTH + " bytes");
        }
        if (headHash == null || headHash.length != AuthorityRecord.HASH_LENGTH) {
            throw new IllegalArgumentException("the head hash must be exactly " + AuthorityRecord.HASH_LENGTH
                    + " bytes");
        }
        if (isAllZero(headHash)) {
            throw new IllegalArgumentException("an empty chain has no head to publish");
        }
        if (headSeq < 1) {
            throw new IllegalArgumentException("an authority head must name a record at position 1 or later");
        }
        byte[] homeserverIdBytes = homeserverId == null
                ? new byte[0]
                : homeserverId.getBytes(StandardCharsets.US_ASCII);
        if (homeserverIdBytes.length < 1
                || homeserverIdBytes.length > AuthorityHeadRecord.MAX_HOMESERVER_ID_LENGTH) {
            throw new IllegalArgumentException("homeserver id must be 1 to "
                    + AuthorityHeadRecord.MAX_HOMESERVER_ID_LENGTH + " bytes");
        }
        // Validates the id with the decoder's rules; the result is not needed.
        decodeHomeserverId(homeserverIdBytes);
        if (!notAfter.isAfter(notBefore)) {
            throw new IllegalArgumentException("notAfter must be after notBefore");
        }
        if (Duration.between(notBefore, notAfter).compareTo(MAX_VALIDITY) > 0) {
            throw new IllegalArgumentException("the validity window is longer than " + MAX_VALIDITY.toDays()
                    + " days");
        }

        byte[] out = new byte[AuthorityHeadRecord.LENGTH_WITHOUT_HOMESERVER_ID + homeserverIdBytes.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[OFFSET_VERSION] = (byte) AuthorityHeadRecord.VERSION;
        out[OFFSET_SUITE] = (byte) AuthorityRecord.SUITE_ED25519_SHA256;
        System.arraycopy(accountReference, 0, out, OFFSET_REFERENCE,
                AuthorityRecord.ACCOUNT_REFERENCE_LENGTH);
        System.arraycopy(headHash, 0, out, OFFSET_HEAD_HASH, AuthorityRecord.HASH_LENGTH);
        writeUnsignedLong(out, OFFSET_HEAD_SEQ, headSeq);
        out[OFFSET_HOMESERVER_LENGTH] = (byte) homeserverIdBytes.length;
        System.arraycopy(homeserverIdBytes, 0, out, OFFSET_HOMESERVER_ID, homeserverIdBytes.length);

        int trailer = OFFSET_HOMESERVER_ID + homeserverIdBytes.length;
        writeUnsignedLong(out, trailer, issuedAt.toEpochMilli());
        writeUnsignedLong(out, trailer + 8, notBefore.toEpochMilli());
        writeUnsignedLong(out, trailer + 16, notAfter.toEpochMilli());
        return out;
    }

    public static byte[] signaturePreimage(byte[] canonicalBytes) {
        byte[] preimage = new byte[MAGIC.length + canonicalBytes.length];
        System.arraycopy(MAGIC, 0, preimage, 0, MAGIC.length);
        System.arraycopy(canonicalBytes, 0, preimage, MAGIC.length, canonicalBytes.length);
        return preimage;
    }

    private static String decodeHomeserverId(byte[] value) {
        for (byte b : value) {
            int c = b & 0xFF;
            if (c <= 0x20 || c >= 0x7F) {
                throw new InvalidAuthorityRecordException("bad_homeserver_id",
                        "homeserver id has a byte outside printable ASCII");
            }
        }
        return new String(value, StandardCharsets.US_ASCII);
    }

    private static boolean isAllZero(byte[] value) {
        for (byte b : value) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static long readUnsignedLong(byte[] bytes, int offset, String reason, String field) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (bytes[offset + i] & 0xFFL);
        }
        if (value < 0) {
            // Unsigned on the wire: a value with the top bit set is refused, not read as negative.
            throw new InvalidAuthorityRecordException(reason, field + " is out of range");
        }
        return value;
    }

    private static void writeUnsignedLong(byte[] out, int offset, long value) {
        if (value < 0) {
            throw new IllegalArgumentException("head positions and timestamps are unsigned");
        }
        for (int i = 0; i < 8; i++) {
            out[offset + i] = (byte) (value >>> (56 - 8 * i));
        }
    }
}
