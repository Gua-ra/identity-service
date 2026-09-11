package me.sarahlacerda.gua.identityservice.account.genesis;

/**
 * A decoded {@code BootstrapGenesis} (ADM-008 suite 0x00), together with the exact bytes it was decoded
 * from.
 *
 * <p>It commits nothing and makes no ADM-001 L4 claim. Its whole job is to give an account that predates
 * account authority, or one created on the web where no genesis design exists yet, an accountId that is
 * re-derivable and auditable, with the root class byte 0x00 marking it as a bootstrap account (L5 path
 * B1). The entropy is random and is never derived from the MXID or the phone: a preimage containing
 * either would put an identifier, and with it the homeserver, inside the id, which L4 forbids and which
 * would turn replicated state into a linkage oracle.
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

    /** Bootstrap-class accountId over those bytes. */
    public AccountId accountId() {
        return AccountId.derive(AccountId.CLASS_BOOTSTRAP, canonicalBytes);
    }
}
