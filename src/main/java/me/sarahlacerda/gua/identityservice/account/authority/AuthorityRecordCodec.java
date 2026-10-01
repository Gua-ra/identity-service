// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.account.genesis.InvalidGenesisException;

/**
 * Canonical fixed-width encoding, big-endian. Hashes and signatures cover these exact bytes.
 *
 * <pre>
 * off len field
 * 0   4   magic, ASCII, one per record type, and the signature domain
 * 4   1   version = 0x01
 * 5   1   suite = 0x01, Ed25519 with SHA-256
 * 6   34  the accountId raw bytes, exactly what AccountId.rawBytes() returns
 * 40  32  prevHash, SHA-256 over the previous record's canonical bytes, 32 zeros in the first
 * 72  8   seq, unsigned, 1 in the first record and exactly one more than the previous
 * 80  ..  body, fixed per type
 * </pre>
 *
 * <pre>
 * GUAA AdoptRoot          deviceKey 32 | recoveryFrameworkId 1 | recoveryAuthorityKey 32 | label 16 | entropy 16   = 177
 * GUAD DeviceGrant        deviceKey 32 | flags 1 | label 16 | authorizingKey 32                                    = 161
 * GUAX DeviceRevoke       deviceKey 32 | reason 1 | authorizingKey 32                                              = 145
 * GUAR AuthorityRecovery  deviceKey 32 | recoveryAuthorityKey 32 | label 16 | entropy 16 | authorization 1
 *                         | authorizingKey 32                                                                     = 209
 * GUAO Oppose             opposedRecordHash 32 | authorizingKey 32                                                = 144
 * </pre>
 */
public final class AuthorityRecordCodec {

    private static final int OFFSET_VERSION = 4;
    private static final int OFFSET_SUITE = 5;
    private static final int OFFSET_ACCOUNT = 6;
    private static final int OFFSET_PREV_HASH = 40;
    private static final int OFFSET_SEQ = 72;
    private static final int OFFSET_BODY = 80;

    private static final int ADOPT_DEVICE_KEY = OFFSET_BODY;
    private static final int ADOPT_FRAMEWORK = 112;
    private static final int ADOPT_RECOVERY_KEY = 113;
    private static final int ADOPT_LABEL = 145;
    private static final int ADOPT_ENTROPY = 161;

    private static final int GRANT_DEVICE_KEY = OFFSET_BODY;
    private static final int GRANT_FLAGS = 112;
    private static final int GRANT_LABEL = 113;
    private static final int GRANT_AUTHORIZING_KEY = 129;

    private static final int REVOKE_DEVICE_KEY = OFFSET_BODY;
    private static final int REVOKE_REASON = 112;
    private static final int REVOKE_AUTHORIZING_KEY = 113;

    private static final int OPPOSE_RECORD_HASH = OFFSET_BODY;
    private static final int OPPOSE_AUTHORIZING_KEY = 112;

    private static final int RECOVER_DEVICE_KEY = OFFSET_BODY;
    private static final int RECOVER_RECOVERY_KEY = 112;
    private static final int RECOVER_LABEL = 144;
    private static final int RECOVER_ENTROPY = 160;
    private static final int RECOVER_AUTHORIZATION = 176;
    private static final int RECOVER_AUTHORIZING_KEY = 177;

    private AuthorityRecordCodec() {
    }

    public static AuthorityRecord decode(byte[] bytes) {
        AuthorityRecordType type = AuthorityRecordType.ofMagic(bytes);
        if (bytes.length != type.length()) {
            throw new InvalidAuthorityRecordException("wrong_length",
                    type + " must be exactly " + type.length() + " bytes");
        }

        int version = bytes[OFFSET_VERSION] & 0xFF;
        if (version != AuthorityRecord.VERSION) {
            throw new InvalidAuthorityRecordException("unknown_version", "unknown authority record version");
        }
        int suite = bytes[OFFSET_SUITE] & 0xFF;
        if (suite != AuthorityRecord.SUITE_ED25519_SHA256) {
            throw new InvalidAuthorityRecordException("unknown_suite", "unknown authority record suite");
        }

        byte[] accountReference = Arrays.copyOfRange(bytes, OFFSET_ACCOUNT, OFFSET_PREV_HASH);
        byte[] prevHash = Arrays.copyOfRange(bytes, OFFSET_PREV_HASH, OFFSET_SEQ);
        long seq = ByteBuffer.wrap(bytes, OFFSET_SEQ, 8).getLong();
        if (seq < 1) {
            throw new InvalidAuthorityRecordException("bad_seq", "seq starts at 1");
        }

        return switch (type) {
            case ADOPT_ROOT -> decodeAdoptRoot(bytes, version, suite, accountReference, prevHash, seq);
            case DEVICE_GRANT -> decodeGrant(bytes, version, suite, accountReference, prevHash, seq);
            case DEVICE_REVOKE -> decodeRevoke(bytes, version, suite, accountReference, prevHash, seq);
            case AUTHORITY_RECOVERY -> decodeRecovery(bytes, version, suite, accountReference, prevHash, seq);
            case OPPOSE -> decodeOppose(bytes, version, suite, accountReference, prevHash, seq);
        };
    }

    private static AuthorityRecord decodeAdoptRoot(byte[] bytes, int version, int suite, byte[] account,
            byte[] prevHash, long seq) {
        byte[] deviceKey = key(bytes, ADOPT_DEVICE_KEY, "device_key");
        int framework = bytes[ADOPT_FRAMEWORK] & 0xFF;
        if (framework != AuthorityRecord.RECOVERY_FRAMEWORK_COMMITTED_KEY) {
            throw new InvalidAuthorityRecordException("unknown_recovery_framework", "unknown recovery framework id");
        }
        byte[] recoveryKey = key(bytes, ADOPT_RECOVERY_KEY, "recovery_key");
        requireDistinct(deviceKey, recoveryKey);
        String label = label(bytes, ADOPT_LABEL);
        byte[] entropy = Arrays.copyOfRange(bytes, ADOPT_ENTROPY, AuthorityRecord.ADOPT_ROOT_LENGTH);

        return new AuthorityRecord(AuthorityRecordType.ADOPT_ROOT, version, suite, account, prevHash, seq,
                deviceKey, framework, recoveryKey, label, entropy, null, null, null, null, null, bytes);
    }

    private static AuthorityRecord decodeGrant(byte[] bytes, int version, int suite, byte[] account,
            byte[] prevHash, long seq) {
        byte[] deviceKey = key(bytes, GRANT_DEVICE_KEY, "device_key");
        int flags = bytes[GRANT_FLAGS] & 0xFF;
        if (flags != AuthorityRecord.FLAGS_NONE) {
            throw new InvalidAuthorityRecordException("unknown_flags", "no grant flag is defined");
        }
        String label = label(bytes, GRANT_LABEL);
        byte[] authorizingKey = key(bytes, GRANT_AUTHORIZING_KEY, "authorizing_key");

        return new AuthorityRecord(AuthorityRecordType.DEVICE_GRANT, version, suite, account, prevHash, seq,
                deviceKey, null, null, label, null, flags, null, null, authorizingKey, null, bytes);
    }

    private static AuthorityRecord decodeRevoke(byte[] bytes, int version, int suite, byte[] account,
            byte[] prevHash, long seq) {
        byte[] deviceKey = key(bytes, REVOKE_DEVICE_KEY, "device_key");
        int reason = bytes[REVOKE_REASON] & 0xFF;
        if (reason < AuthorityRecord.REASON_UNSPECIFIED || reason > AuthorityRecord.REASON_COMPROMISED) {
            throw new InvalidAuthorityRecordException("unknown_revocation_reason", "unknown revocation reason");
        }
        byte[] authorizingKey = key(bytes, REVOKE_AUTHORIZING_KEY, "authorizing_key");

        return new AuthorityRecord(AuthorityRecordType.DEVICE_REVOKE, version, suite, account, prevHash, seq,
                deviceKey, null, null, null, null, null, reason, null, authorizingKey, null, bytes);
    }

    private static AuthorityRecord decodeRecovery(byte[] bytes, int version, int suite, byte[] account,
            byte[] prevHash, long seq) {
        byte[] deviceKey = key(bytes, RECOVER_DEVICE_KEY, "device_key");
        byte[] recoveryKey = key(bytes, RECOVER_RECOVERY_KEY, "recovery_key");
        requireDistinct(deviceKey, recoveryKey);
        String label = label(bytes, RECOVER_LABEL);
        byte[] entropy = Arrays.copyOfRange(bytes, RECOVER_ENTROPY, RECOVER_AUTHORIZATION);
        int authorization = bytes[RECOVER_AUTHORIZATION] & 0xFF;
        byte[] authorizingKeyField =
                Arrays.copyOfRange(bytes, RECOVER_AUTHORIZING_KEY, AuthorityRecord.AUTHORITY_RECOVERY_LENGTH);

        byte[] authorizingKey;
        switch (authorization) {
            case AuthorityRecord.AUTHORIZATION_RECOVERY_KEY -> {
                if (Ed25519Keys.isAllZero(authorizingKeyField)) {
                    throw new InvalidAuthorityRecordException("authorizing_key_required",
                            "the recovery-key authorization must name the key that signs it");
                }
                onCurve(authorizingKeyField, "invalid_authorizing_key");
                authorizingKey = authorizingKeyField;
            }
            case AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY -> {
                if (!Ed25519Keys.isAllZero(authorizingKeyField)) {
                    throw new InvalidAuthorityRecordException("authorizing_key_not_permitted",
                            "the account-recovery authorization names no authorizing key");
                }
                authorizingKey = null;
            }
            default -> throw new InvalidAuthorityRecordException("unknown_authorization",
                    "unknown recovery authorization");
        }

        return new AuthorityRecord(AuthorityRecordType.AUTHORITY_RECOVERY, version, suite, account, prevHash, seq,
                deviceKey, null, recoveryKey, label, entropy, null, null, authorization, authorizingKey, null,
                bytes);
    }

    private static AuthorityRecord decodeOppose(byte[] bytes, int version, int suite, byte[] account,
            byte[] prevHash, long seq) {
        byte[] opposed = Arrays.copyOfRange(bytes, OPPOSE_RECORD_HASH, OPPOSE_AUTHORIZING_KEY);
        if (Ed25519Keys.isAllZero(opposed)) {
            throw new InvalidAuthorityRecordException("zero_opposed_record", "the opposed record hash is all zero");
        }
        byte[] authorizingKey = key(bytes, OPPOSE_AUTHORIZING_KEY, "authorizing_key");

        return new AuthorityRecord(AuthorityRecordType.OPPOSE, version, suite, account, prevHash, seq,
                null, null, null, null, null, null, null, null, authorizingKey, opposed, bytes);
    }

    /** The all-zero check is separate because all-zero bytes decode to a valid low-order point. */
    private static byte[] key(byte[] bytes, int offset, String field) {
        byte[] raw = Arrays.copyOfRange(bytes, offset, offset + AuthorityRecord.KEY_LENGTH);
        if (Ed25519Keys.isAllZero(raw)) {
            throw new InvalidAuthorityRecordException("zero_" + field, field + " is all zero");
        }
        onCurve(raw, "invalid_" + field);
        return raw;
    }

    private static void onCurve(byte[] raw, String reason) {
        try {
            Ed25519Keys.fromRaw(raw, reason);
        } catch (InvalidGenesisException ex) {
            throw new InvalidAuthorityRecordException(reason, "Ed25519 key does not decode to a curve point", ex);
        }
    }

    private static void requireDistinct(byte[] deviceKey, byte[] recoveryKey) {
        if (MessageDigest.isEqual(deviceKey, recoveryKey)) {
            throw new InvalidAuthorityRecordException("duplicate_keys",
                    "the recovery authority key must differ from the device key");
        }
    }

    private static String label(byte[] bytes, int offset) {
        byte[] raw = Arrays.copyOfRange(bytes, offset, offset + AuthorityRecord.LABEL_LENGTH);
        int end = raw.length;
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] == 0) {
                end = i;
                break;
            }
        }
        for (int i = end; i < raw.length; i++) {
            if (raw[i] != 0) {
                throw new InvalidAuthorityRecordException("non_canonical_label",
                        "a label is zero-padded to its end");
            }
        }
        return new String(raw, 0, end, StandardCharsets.UTF_8);
    }

    /** For tests and vector generation only. The server never re-encodes a record it received. */
    public static byte[] encode(AuthorityRecordType type, byte[] accountReference, byte[] prevHash, long seq,
            byte[] body) {
        if (accountReference.length != AuthorityRecord.ACCOUNT_REFERENCE_LENGTH) {
            throw new IllegalArgumentException("the account reference is "
                    + AuthorityRecord.ACCOUNT_REFERENCE_LENGTH + " bytes");
        }
        if (prevHash.length != AuthorityRecord.HASH_LENGTH) {
            throw new IllegalArgumentException("prevHash is " + AuthorityRecord.HASH_LENGTH + " bytes");
        }
        if (body.length != type.length() - OFFSET_BODY) {
            throw new IllegalArgumentException(type + " body is " + (type.length() - OFFSET_BODY) + " bytes");
        }
        byte[] out = new byte[type.length()];
        byte[] magic = type.magicBytes();
        System.arraycopy(magic, 0, out, 0, magic.length);
        out[OFFSET_VERSION] = (byte) AuthorityRecord.VERSION;
        out[OFFSET_SUITE] = (byte) AuthorityRecord.SUITE_ED25519_SHA256;
        System.arraycopy(accountReference, 0, out, OFFSET_ACCOUNT, AuthorityRecord.ACCOUNT_REFERENCE_LENGTH);
        System.arraycopy(prevHash, 0, out, OFFSET_PREV_HASH, AuthorityRecord.HASH_LENGTH);
        ByteBuffer.wrap(out, OFFSET_SEQ, 8).putLong(seq);
        System.arraycopy(body, 0, out, OFFSET_BODY, body.length);
        return out;
    }

    public static byte[] labelBytes(String label) {
        byte[] utf8 = label == null ? new byte[0] : label.getBytes(StandardCharsets.UTF_8);
        if (utf8.length > AuthorityRecord.LABEL_LENGTH) {
            throw new IllegalArgumentException("a label is at most " + AuthorityRecord.LABEL_LENGTH + " bytes");
        }
        return Arrays.copyOf(utf8, AuthorityRecord.LABEL_LENGTH);
    }
}
