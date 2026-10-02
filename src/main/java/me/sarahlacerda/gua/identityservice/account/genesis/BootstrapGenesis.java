package me.sarahlacerda.gua.identityservice.account.genesis;

/**
 * A decoded bootstrap genesis (suite 0x00) together with the exact bytes it was decoded from.
 *
 * <p>It commits nothing. It gives an account without an authority key a re-derivable, auditable
 * accountId whose root class byte 0x00 marks it as bootstrap. The entropy is random and never derived
 * from the MXID or the phone, which would put an identifier inside the id.
 */
public final class BootstrapGenesis {

    /** Total canonical length. Any other length is rejected. */
    public static final int LENGTH = 22;

    /** ASCII {@code GUAB}, the domain separator. */
    public static final String MAGIC = "GUAB";

    public static final int VERSION = 0x01;

    /** No authority key. */
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

    /** The bytes as received or as minted. Stored so the id stays re-derivable and auditable. */
    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }

    public AccountId accountId() {
        return AccountId.derive(AccountId.CLASS_BOOTSTRAP, canonicalBytes);
    }
}
