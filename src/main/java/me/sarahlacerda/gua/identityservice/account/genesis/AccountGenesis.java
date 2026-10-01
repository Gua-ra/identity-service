package me.sarahlacerda.gua.identityservice.account.genesis;

public final class AccountGenesis {

    public static final int LENGTH = 87;

    public static final String MAGIC = "GUAG";

    public static final int VERSION = 0x01;

    public static final int SUITE_ED25519_SHA256 = 0x01;

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

    /** The bytes as received. The accountId hashes these, never a re-encoding. */
    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }

    public AccountId accountId() {
        return AccountId.derive(AccountId.CLASS_GENESIS, canonicalBytes);
    }
}
