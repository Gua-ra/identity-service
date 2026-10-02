package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;

/**
 * The two possession proofs and the fixed-length preimages they cover.
 *
 * <p><b>Registration proof.</b> An Ed25519 signature by the authority key over the ASCII domain
 * {@code gua-account-genesis-proof.v1} followed by the canonical genesis bytes. No identifier appears
 * in the preimage.
 *
 * <p><b>Attach proof.</b> An Ed25519 signature by the same authority key over the domain
 * {@code gua-account-attach-proof.v1}, then the 32 server-chosen challenge bytes, then the 34 raw
 * accountId bytes (27 + 32 + 34, all fixed length). A handle alone attaches nothing: only this
 * signature shows the registrant held the key and was present in this login session.
 */
public final class GenesisProofs {

    public static final String GENESIS_PROOF_DOMAIN = "gua-account-genesis-proof.v1";

    public static final String ATTACH_PROOF_DOMAIN = "gua-account-attach-proof.v1";

    /** Server-chosen challenge length, in bytes. */
    public static final int ATTACH_CHALLENGE_LENGTH = 32;

    private static final byte[] GENESIS_DOMAIN_BYTES = GENESIS_PROOF_DOMAIN.getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ATTACH_DOMAIN_BYTES = ATTACH_PROOF_DOMAIN.getBytes(StandardCharsets.US_ASCII);

    public static final int ATTACH_PREIMAGE_LENGTH =
            ATTACH_DOMAIN_BYTES.length + ATTACH_CHALLENGE_LENGTH + AccountId.RAW_LENGTH;

    private GenesisProofs() {
    }

    public static byte[] genesisProofPreimage(byte[] canonicalBytes) {
        byte[] preimage = new byte[GENESIS_DOMAIN_BYTES.length + canonicalBytes.length];
        System.arraycopy(GENESIS_DOMAIN_BYTES, 0, preimage, 0, GENESIS_DOMAIN_BYTES.length);
        System.arraycopy(canonicalBytes, 0, preimage, GENESIS_DOMAIN_BYTES.length, canonicalBytes.length);
        return preimage;
    }

    /**
     * Domain bytes, then the challenge, then the raw accountId bytes. Fixed length throughout.
     *
     * @param challenge the 32 server-chosen bytes held against the login session
     * @param accountId the accountId the server derived from the stored genesis, never one from a request
     */
    public static byte[] attachProofPreimage(byte[] challenge, AccountId accountId) {
        if (challenge == null || challenge.length != ATTACH_CHALLENGE_LENGTH) {
            throw new IllegalArgumentException("attach challenge is " + ATTACH_CHALLENGE_LENGTH + " bytes");
        }
        byte[] raw = accountId.rawBytes();
        byte[] preimage = new byte[ATTACH_PREIMAGE_LENGTH];
        int offset = 0;
        System.arraycopy(ATTACH_DOMAIN_BYTES, 0, preimage, offset, ATTACH_DOMAIN_BYTES.length);
        offset += ATTACH_DOMAIN_BYTES.length;
        System.arraycopy(challenge, 0, preimage, offset, ATTACH_CHALLENGE_LENGTH);
        offset += ATTACH_CHALLENGE_LENGTH;
        System.arraycopy(raw, 0, preimage, offset, AccountId.RAW_LENGTH);
        return preimage;
    }

    /** Verifies the registration proof against the key inside the genesis itself. */
    public static boolean verifyGenesisProof(AccountGenesis genesis, byte[] signature) {
        return Ed25519Keys.verify(genesis.authorityPublicKey(),
                genesisProofPreimage(genesis.canonicalBytes()), signature);
    }

    /**
     * Verifies the attach proof.
     *
     * @param authorityPublicKey the key inside the stored genesis, never one supplied by the caller
     */
    public static boolean verifyAttachProof(byte[] authorityPublicKey, byte[] challenge, AccountId accountId,
            byte[] signature) {
        return Ed25519Keys.verify(authorityPublicKey, attachProofPreimage(challenge, accountId), signature);
    }
}
