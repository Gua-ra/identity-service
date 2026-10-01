package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;

/** Possession-proof preimages. Every element is fixed length and none contains an identifier. */
public final class GenesisProofs {

    public static final String GENESIS_PROOF_DOMAIN = "gua-account-genesis-proof.v1";

    public static final String ATTACH_PROOF_DOMAIN = "gua-account-attach-proof.v1";

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

    public static boolean verifyGenesisProof(AccountGenesis genesis, byte[] signature) {
        return Ed25519Keys.verify(genesis.authorityPublicKey(),
                genesisProofPreimage(genesis.canonicalBytes()), signature);
    }

    /** The key must come from the stored genesis, never from the caller. */
    public static boolean verifyAttachProof(byte[] authorityPublicKey, byte[] challenge, AccountId accountId,
            byte[] signature) {
        return Ed25519Keys.verify(authorityPublicKey, attachProofPreimage(challenge, accountId), signature);
    }
}
