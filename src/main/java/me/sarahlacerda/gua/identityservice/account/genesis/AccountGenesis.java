package me.sarahlacerda.gua.identityservice.account.genesis;

/**
 * A decoded {@code AccountGenesis} (ADM-008 suite 0x01), together with the exact bytes it was decoded
 * from. Immutable: every accessor hands back a copy, so nothing downstream can mutate the bytes the
 * accountId is derived from.
 *
 * <p>It commits the initial authority key, the algorithm identifiers and the initial recovery authority
 * and framework, and it holds no identifier and no homeserver (ADM-001 L4).
 */
public final class AccountGenesis {

    /** Total canonical length. Any other length is rejected. */
    public static final int LENGTH = 87;

    /** ASCII {@code GUAG}, the domain separator. */
    public static final String MAGIC = "GUAG";

    public static final int VERSION = 0x01;

    /** Ed25519 authority, Ed25519 recovery, SHA-256. */
    public static final int SUITE_ED25519_SHA256 = 0x01;

    /** One committed recovery authority key (ADM-008 decision 4). */
    public static final int RECOVERY_FRAMEWORK_COMMITTED_KEY = 0x01;

    public static final int ENTROPY_LENGTH = 16;

    private final int genesisVersion;
    private final int suite;
    private final byte[] authorityPublicKey;
    private final int recoveryFrameworkId;
    private final byte[] recoveryAuthorityPublicKey;
    private final byte[] entropy;
    private final byte[] canonicalBytes;

    AccountGenesis(int genesisVersion, int suite, byte[] authorityPublicKey, int recoveryFrameworkId,
            byte[] recoveryAuthorityPublicKey, byte[] entropy, byte[] canonicalBytes) {
        this.genesisVersion = genesisVersion;
        this.suite = suite;
        this.authorityPublicKey = authorityPublicKey.clone();
        this.recoveryFrameworkId = recoveryFrameworkId;
        this.recoveryAuthorityPublicKey = recoveryAuthorityPublicKey.clone();
        this.entropy = entropy.clone();
        this.canonicalBytes = canonicalBytes.clone();
    }

    public int genesisVersion() {
        return genesisVersion;
    }

    public int suite() {
        return suite;
    }

    /** The raw 32-byte Ed25519 account authority key. */
    public byte[] authorityPublicKey() {
        return authorityPublicKey.clone();
    }

    public int recoveryFrameworkId() {
        return recoveryFrameworkId;
    }

    public byte[] recoveryAuthorityPublicKey() {
        return recoveryAuthorityPublicKey.clone();
    }

    public byte[] entropy() {
        return entropy.clone();
    }

    /** The bytes as received. The accountId is the hash of these, never of a re-encoding. */
    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }

    /** Genesis-rooted accountId over the received bytes. */
    public AccountId accountId() {
        return AccountId.derive(AccountId.CLASS_GENESIS, canonicalBytes);
    }
}
