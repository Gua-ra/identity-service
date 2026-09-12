package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * The canonical codec for {@code AccountGenesis}, suite 0x01 (ADM-008 encoding tables).
 *
 * <pre>
 * off len field
 * 0   4   magic "GUAG"
 * 4   1   genesisVersion = 0x01
 * 5   1   suite = 0x01
 * 6   32  authorityPublicKey          raw RFC 8032 Ed25519
 * 38  1   recoveryFrameworkId = 0x01
 * 39  32  recoveryAuthorityPublicKey  raw Ed25519, must differ from the authority key
 * 71  16  entropy                     CSPRNG
 * 87      end
 * </pre>
 *
 * <h2>Why a fixed layout instead of ADM-007's {@code gua-lp.v1}</h2>
 * <p>ADM-007 fixes {@code gua-lp.v1} for the roster, member and governance objects: a u32 length before
 * every field and a schema tag opening every object. Where it already defines a primitive this package
 * follows it rather than inventing a second rule, which is why the placement timestamps these objects
 * will later travel with are epoch milliseconds in 8 big-endian bytes, and why an object hash is SHA-256
 * over the canonical bytes.
 *
 * <p>The account objects themselves keep fixed layouts, for the reason ADM-008 gives in its
 * "Relationship to ADM-007" section. They have no optional fields, no sets and no free strings, so
 * length prefixes would describe nothing that is not already constant. More importantly the accountId is
 * a permanent hash of these bytes, so the bytes that are hashed must be the bytes that crossed the wire;
 * a framing with a parse-then-re-serialize step invites exactly the re-encoding this must never do.
 * Both families still obey the same two ADM-001 L4 rules: one canonical byte representation, and
 * signatures over those bytes. They cannot be confused either, because a {@code gua-lp.v1} object opens
 * with a u32 length whose first byte is 0x00 while an account object opens with ASCII {@code GUA}.
 *
 * <p>The decoder rejects an unknown version, suite or framework, a wrong length, an all-zero key, equal
 * authority and recovery keys, and a key that fails Ed25519 point decoding. The all-zero rule is separate
 * from point decoding on purpose: the all-zero encoding decodes to a valid low-order point.
 */
public final class AccountGenesisCodec {

    private static final byte[] MAGIC = AccountGenesis.MAGIC.getBytes(StandardCharsets.US_ASCII);

    private static final int OFFSET_VERSION = 4;
    private static final int OFFSET_SUITE = 5;
    private static final int OFFSET_AUTHORITY_KEY = 6;
    private static final int OFFSET_FRAMEWORK = 38;
    private static final int OFFSET_RECOVERY_KEY = 39;
    private static final int OFFSET_ENTROPY = 71;

    private AccountGenesisCodec() {
    }

    /**
     * Strictly decodes canonical bytes. The returned object keeps the bytes exactly as passed in, so the
     * accountId is derived from what was received.
     *
     * @throws InvalidGenesisException on any rule ADM-008 decision 1 states
     */
    public static AccountGenesis decode(byte[] bytes) {
        if (bytes == null || bytes.length != AccountGenesis.LENGTH) {
            throw new InvalidGenesisException("wrong_length",
                    "AccountGenesis must be exactly " + AccountGenesis.LENGTH + " bytes");
        }
        if (!MessageDigest.isEqual(Arrays.copyOfRange(bytes, 0, MAGIC.length), MAGIC)) {
            throw new InvalidGenesisException("bad_magic", "AccountGenesis magic is not " + AccountGenesis.MAGIC);
        }
        int version = bytes[OFFSET_VERSION] & 0xFF;
        if (version != AccountGenesis.VERSION) {
            throw new InvalidGenesisException("unknown_version", "unknown AccountGenesis version");
        }
        int suite = bytes[OFFSET_SUITE] & 0xFF;
        if (suite != AccountGenesis.SUITE_ED25519_SHA256) {
            throw new InvalidGenesisException("unknown_suite", "unknown AccountGenesis suite");
        }
        int frameworkId = bytes[OFFSET_FRAMEWORK] & 0xFF;
        if (frameworkId != AccountGenesis.RECOVERY_FRAMEWORK_COMMITTED_KEY) {
            throw new InvalidGenesisException("unknown_recovery_framework", "unknown recovery framework id");
        }

        byte[] authorityKey = Arrays.copyOfRange(bytes, OFFSET_AUTHORITY_KEY, OFFSET_FRAMEWORK);
        byte[] recoveryKey = Arrays.copyOfRange(bytes, OFFSET_RECOVERY_KEY, OFFSET_ENTROPY);
        byte[] entropy = Arrays.copyOfRange(bytes, OFFSET_ENTROPY, AccountGenesis.LENGTH);

        if (Ed25519Keys.isAllZero(authorityKey)) {
            throw new InvalidGenesisException("zero_authority_key", "authority key is all zero");
        }
        if (Ed25519Keys.isAllZero(recoveryKey)) {
            throw new InvalidGenesisException("zero_recovery_key", "recovery authority key is all zero");
        }
        if (MessageDigest.isEqual(authorityKey, recoveryKey)) {
            throw new InvalidGenesisException("duplicate_keys",
                    "recovery authority key must differ from the authority key");
        }
        Ed25519Keys.fromRaw(authorityKey, "invalid_authority_key");
        Ed25519Keys.fromRaw(recoveryKey, "invalid_recovery_key");

        return new AccountGenesis(version, suite, authorityKey, frameworkId, recoveryKey, entropy, bytes);
    }

    /**
     * Builds canonical bytes. Used by tests and by the golden-vector generator; the server never encodes
     * a genesis it is about to hash, it hashes what it received.
     */
    public static byte[] encode(byte[] authorityPublicKey, int recoveryFrameworkId,
            byte[] recoveryAuthorityPublicKey, byte[] entropy) {
        if (authorityPublicKey.length != Ed25519Keys.RAW_PUBLIC_KEY_LENGTH
                || recoveryAuthorityPublicKey.length != Ed25519Keys.RAW_PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public keys are 32 bytes");
        }
        if (entropy.length != AccountGenesis.ENTROPY_LENGTH) {
            throw new IllegalArgumentException("entropy is " + AccountGenesis.ENTROPY_LENGTH + " bytes");
        }
        byte[] out = new byte[AccountGenesis.LENGTH];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[OFFSET_VERSION] = (byte) AccountGenesis.VERSION;
        out[OFFSET_SUITE] = (byte) AccountGenesis.SUITE_ED25519_SHA256;
        System.arraycopy(authorityPublicKey, 0, out, OFFSET_AUTHORITY_KEY, Ed25519Keys.RAW_PUBLIC_KEY_LENGTH);
        out[OFFSET_FRAMEWORK] = (byte) recoveryFrameworkId;
        System.arraycopy(recoveryAuthorityPublicKey, 0, out, OFFSET_RECOVERY_KEY, Ed25519Keys.RAW_PUBLIC_KEY_LENGTH);
        System.arraycopy(entropy, 0, out, OFFSET_ENTROPY, AccountGenesis.ENTROPY_LENGTH);
        return out;
    }
}
