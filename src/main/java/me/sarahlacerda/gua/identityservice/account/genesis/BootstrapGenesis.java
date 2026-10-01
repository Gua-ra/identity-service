package me.sarahlacerda.gua.identityservice.account.genesis;

// Gives an account without an authority key a re-derivable accountId.
// The entropy is random, never derived from the MXID or the phone.
public final class BootstrapGenesis {

    public static final int LENGTH = 22;

    public static final String MAGIC = "GUAB";

    public static final int VERSION = 0x01;

    public static final int SUITE_NONE = 0x00;

    public static final int ENTROPY_LENGTH = 16;

    private final int version;
    private final int suite;
    private final byte[] entropy;
    private final byte[] canonicalBytes;

    BootstrapGenesis(int version, int suite, byte[] entropy, byte[] canonicalBytes) {
        this.version = version;
        this.suite = suite;
        this.entropy = entropy.clone();
        this.canonicalBytes = canonicalBytes.clone();
    }

    public int version() {
        return version;
    }

    public int suite() {
        return suite;
    }

    public byte[] entropy() {
        return entropy.clone();
    }

    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }

    public AccountId accountId() {
        return AccountId.derive(AccountId.CLASS_BOOTSTRAP, canonicalBytes);
    }
}
