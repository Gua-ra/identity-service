package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** Canonical fixed-width encoding. The accountId hashes the exact bytes received. */
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
