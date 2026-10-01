// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/** A decoded record. Keeps the received bytes verbatim because hashes and signatures cover them. */
public final class AuthorityRecord {

    public static final int MAGIC_LENGTH = 4;

    public static final int VERSION = 0x01;

    public static final int SUITE_ED25519_SHA256 = 0x01;

    /**
     * Duplicates the AccountId length on purpose: this package must not reference that type
     * (AccountIdNotReadGuardTest).
     */
    public static final int ACCOUNT_REFERENCE_LENGTH = 34;

    public static final int HASH_LENGTH = 32;

    public static final int KEY_LENGTH = 32;

    public static final int LABEL_LENGTH = 16;

    public static final int ENTROPY_LENGTH = 16;

    public static final int CHALLENGE_LENGTH = 32;

    public static final int ENVELOPE_LENGTH = 80;

    public static final int ADOPT_ROOT_LENGTH = 177;
    public static final int DEVICE_GRANT_LENGTH = 161;
    public static final int DEVICE_REVOKE_LENGTH = 145;
    public static final int AUTHORITY_RECOVERY_LENGTH = 209;
    public static final int OPPOSE_LENGTH = 144;

    public static final int RECOVERY_FRAMEWORK_COMMITTED_KEY = 0x01;

    public static final int FLAGS_NONE = 0x00;

    public static final int REASON_UNSPECIFIED = 0x01;
    public static final int REASON_LOST = 0x02;
    public static final int REASON_REPLACED = 0x03;
    public static final int REASON_COMPROMISED = 0x04;

    public static final int AUTHORIZATION_RECOVERY_KEY = 0x01;
    public static final int AUTHORIZATION_ACCOUNT_RECOVERY = 0x02;

    private final AuthorityRecordType type;
    private final int version;
    private final int suite;
    private final byte[] accountReference;
    private final byte[] prevHash;
    private final long seq;
    private final byte[] deviceKey;
    private final Integer recoveryFrameworkId;
    private final byte[] recoveryAuthorityKey;
    private final String label;
    private final byte[] entropy;
    private final Integer flags;
    private final Integer reason;
    private final Integer authorization;
    private final byte[] authorizingKey;
    private final byte[] opposedRecordHash;
    private final byte[] canonicalBytes;

    AuthorityRecord(AuthorityRecordType type, int version, int suite, byte[] accountReference, byte[] prevHash,
            long seq, byte[] deviceKey, Integer recoveryFrameworkId, byte[] recoveryAuthorityKey, String label,
            byte[] entropy, Integer flags, Integer reason, Integer authorization, byte[] authorizingKey,
            byte[] opposedRecordHash, byte[] canonicalBytes) {
        this.type = type;
        this.version = version;
        this.suite = suite;
        this.accountReference = accountReference;
        this.prevHash = prevHash;
        this.seq = seq;
        this.deviceKey = deviceKey;
        this.recoveryFrameworkId = recoveryFrameworkId;
        this.recoveryAuthorityKey = recoveryAuthorityKey;
        this.label = label;
        this.entropy = entropy;
        this.flags = flags;
        this.reason = reason;
        this.authorization = authorization;
        this.authorizingKey = authorizingKey;
        this.opposedRecordHash = opposedRecordHash;
        this.canonicalBytes = canonicalBytes;
    }

    public AuthorityRecordType type() {
        return type;
    }

    public int version() {
        return version;
    }

    public int suite() {
        return suite;
    }

    public byte[] accountReference() {
        return accountReference.clone();
    }

    public byte[] prevHash() {
        return prevHash.clone();
    }

    public String prevHashHex() {
        return HexFormat.of().formatHex(prevHash);
    }

    public long seq() {
        return seq;
    }

    public byte[] deviceKey() {
        return deviceKey == null ? null : deviceKey.clone();
    }

    public byte[] opposedRecordHash() {
        return opposedRecordHash == null ? null : opposedRecordHash.clone();
    }

    public String opposedRecordHashHex() {
        return opposedRecordHash == null ? null : HexFormat.of().formatHex(opposedRecordHash);
    }

    public Integer recoveryFrameworkId() {
        return recoveryFrameworkId;
    }

    public byte[] recoveryAuthorityKey() {
        return recoveryAuthorityKey == null ? null : recoveryAuthorityKey.clone();
    }

    public String label() {
        return label;
    }

    public byte[] entropy() {
        return entropy == null ? null : entropy.clone();
    }

    public Integer flags() {
        return flags;
    }

    public Integer reason() {
        return reason;
    }

    public Integer authorization() {
        return authorization;
    }

    public byte[] verifyingKey() {
        return authorizingKey == null ? deviceKey.clone() : authorizingKey.clone();
    }

    public byte[] authorizingKeyField() {
        return authorizingKey == null ? null : authorizingKey.clone();
    }

    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }

    public String hashHex() {
        return HexFormat.of().formatHex(sha256(canonicalBytes));
    }

    public boolean isSelfRevocation() {
        return type == AuthorityRecordType.DEVICE_REVOKE
                && MessageDigest.isEqual(deviceKey, verifyingKey());
    }

    static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", ex);
        }
    }

    public static byte[] emptyPrevHash() {
        return new byte[HASH_LENGTH];
    }

    public static String emptyHeadHash() {
        return HexFormat.of().formatHex(new byte[HASH_LENGTH]);
    }

    @Override
    public String toString() {
        return type + "#" + seq;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof AuthorityRecord record
                && MessageDigest.isEqual(canonicalBytes, record.canonicalBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(canonicalBytes);
    }
}
