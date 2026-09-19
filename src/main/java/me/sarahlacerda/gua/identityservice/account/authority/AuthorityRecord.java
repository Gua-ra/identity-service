// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * One decoded authority-chain record, holding the exact bytes it was decoded from (ADM-009 decision 2).
 *
 * <p>The bytes are kept verbatim for the same reason the genesis objects keep theirs: the record hash is
 * what the next record's {@code prevHash} must equal and what a future log leaf will commit, so the bytes
 * that are hashed have to be the bytes that crossed the wire. Nothing here re-encodes.
 *
 * <p>Fields absent from a type are null or zero: {@code recoveryAuthorityKey} and {@code entropy} only
 * exist on {@link AuthorityRecordType#ADOPT_ROOT} and {@link AuthorityRecordType#AUTHORITY_RECOVERY},
 * {@code label} on those two and on a grant, {@code reason} only on a revocation,
 * {@code authorization} only on a recovery.
 */
public final class AuthorityRecord {

    /** ASCII magic bytes, also the signature domain. */
    public static final int MAGIC_LENGTH = 4;

    /** Record version, the only accepted value. */
    public static final int VERSION = 0x01;

    /** Ed25519 with SHA-256, the only accepted suite. */
    public static final int SUITE_ED25519_SHA256 = 0x01;

    /**
     * Length of the accountId reference the envelope carries, which is exactly the 34 bytes
     * {@code AccountId.rawBytes()} returns.
     *
     * <p>Spelled out here rather than read off that constant so this package does not name the type.
     * {@code AccountIdNotReadGuardTest} allows exactly one new file to resolve an accountId, because MAS
     * derives the Matrix localpart from an arbitrary Jinja template over the imported claims and an
     * accountId would pass its localpart rules; a codec that never resolves one has no business naming
     * it. {@code AccountAuthorityGuardTest} pins the two constants together so they cannot drift.
     */
    public static final int ACCOUNT_REFERENCE_LENGTH = 34;

    /** SHA-256, hex in storage, raw in a preimage. */
    public static final int HASH_LENGTH = 32;

    /** Raw Ed25519 public key. */
    public static final int KEY_LENGTH = 32;

    /** Labels are 16 bytes of UTF-8, zero-padded. What a notification is allowed to name. */
    public static final int LABEL_LENGTH = 16;

    /** CSPRNG entropy, as every account object carries. */
    public static final int ENTROPY_LENGTH = 16;

    /** Server challenge, inside every signature. */
    public static final int CHALLENGE_LENGTH = 32;

    /** Envelope: magic, version, suite, account reference, prevHash, seq. */
    public static final int ENVELOPE_LENGTH = 80;

    public static final int ADOPT_ROOT_LENGTH = 177;
    public static final int DEVICE_GRANT_LENGTH = 161;
    public static final int DEVICE_REVOKE_LENGTH = 145;
    public static final int AUTHORITY_RECOVERY_LENGTH = 209;

    /** The only recovery framework the chain accepts, as ADM-008 decision 4 fixes it. */
    public static final int RECOVERY_FRAMEWORK_COMMITTED_KEY = 0x01;

    /** Reserved. No flag bit has a meaning yet, so any other value is refused rather than ignored. */
    public static final int FLAGS_NONE = 0x00;

    /** The account holder gave no reason. */
    public static final int REASON_UNSPECIFIED = 0x01;
    /** The device is gone. */
    public static final int REASON_LOST = 0x02;
    /** A replacement device has been granted. */
    public static final int REASON_REPLACED = 0x03;
    /** The device is believed to be in someone else's hands. */
    public static final int REASON_COMPROMISED = 0x04;

    /** Authorized by the committed recovery authority key. Rank 2 of decision 3. */
    public static final int AUTHORIZATION_RECOVERY_KEY = 0x01;
    /** Authorized through a completed account recovery. Rank 0 of decision 3. */
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
    private final byte[] canonicalBytes;

    AuthorityRecord(AuthorityRecordType type, int version, int suite, byte[] accountReference, byte[] prevHash,
            long seq, byte[] deviceKey, Integer recoveryFrameworkId, byte[] recoveryAuthorityKey, String label,
            byte[] entropy, Integer flags, Integer reason, Integer authorization, byte[] authorizingKey,
            byte[] canonicalBytes) {
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

    /** The 34 bytes at offset 6, which name the account this record belongs to. */
    public byte[] accountReference() {
        return accountReference.clone();
    }

    /** SHA-256 over the previous record's canonical bytes, or 32 zero bytes in the first record. */
    public byte[] prevHash() {
        return prevHash.clone();
    }

    /** Lowercase hex of {@link #prevHash()}, the form the head row stores. */
    public String prevHashHex() {
        return HexFormat.of().formatHex(prevHash);
    }

    public long seq() {
        return seq;
    }

    /** The device authority key this record activates, or names for removal. */
    public byte[] deviceKey() {
        return deviceKey.clone();
    }

    /** Only on {@link AuthorityRecordType#ADOPT_ROOT}. */
    public Integer recoveryFrameworkId() {
        return recoveryFrameworkId;
    }

    /** The recovery authority key this record commits, on adoption and on recovery. */
    public byte[] recoveryAuthorityKey() {
        return recoveryAuthorityKey == null ? null : recoveryAuthorityKey.clone();
    }

    /** The label with its zero padding trimmed, possibly empty, never null on a type that carries one. */
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

    /** {@link #AUTHORIZATION_RECOVERY_KEY} or {@link #AUTHORIZATION_ACCOUNT_RECOVERY}, recovery only. */
    public Integer authorization() {
        return authorization;
    }

    /**
     * The key whose signature authorizes this record, inside the hashed bytes.
     *
     * <p>Present as a field on a grant, a revocation and a recovery, so a later log leaf commits who
     * authorized each transition and not only that someone did. On the types that carry no such field,
     * and on the account-recovery authorization where it is all zero by rule, this returns the key that
     * actually signs, which is the record's own device key. The server checks that it equals the
     * verifying key rather than inferring the key from it.
     */
    public byte[] verifyingKey() {
        return authorizingKey == null ? deviceKey.clone() : authorizingKey.clone();
    }

    /** The field as encoded, which is all zero under {@link #AUTHORIZATION_ACCOUNT_RECOVERY}. */
    public byte[] authorizingKeyField() {
        return authorizingKey == null ? null : authorizingKey.clone();
    }

    /** The bytes as received. Never a re-encoding. */
    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }

    /** SHA-256 over the canonical bytes, lowercase hex. What the next record's prevHash must equal. */
    public String hashHex() {
        return HexFormat.of().formatHex(sha256(canonicalBytes));
    }

    /** True when the record removes the very key that signed it, which takes effect immediately. */
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

    /** 32 zero bytes, the {@code prevHash} of a first record. */
    public static byte[] emptyPrevHash() {
        return new byte[HASH_LENGTH];
    }

    /** 64 zeros, the hex form the head row holds while a chain is empty. */
    public static String emptyHeadHash() {
        return HexFormat.of().formatHex(new byte[HASH_LENGTH]);
    }

    @Override
    public String toString() {
        // Never the bytes and never a key: a record is logged by its type and position only.
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
