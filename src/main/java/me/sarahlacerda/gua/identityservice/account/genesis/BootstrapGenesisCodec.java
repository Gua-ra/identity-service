package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public final class BootstrapGenesisCodec {

    private static final byte[] MAGIC = BootstrapGenesis.MAGIC.getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int OFFSET_VERSION = 4;
    private static final int OFFSET_SUITE = 5;
    private static final int OFFSET_ENTROPY = 6;

    private BootstrapGenesisCodec() {
    }

    public static BootstrapGenesis decode(byte[] bytes) {
        if (bytes == null || bytes.length != BootstrapGenesis.LENGTH) {
            throw new InvalidGenesisException("wrong_length",
                    "BootstrapGenesis must be exactly " + BootstrapGenesis.LENGTH + " bytes");
        }
        if (!MessageDigest.isEqual(Arrays.copyOfRange(bytes, 0, MAGIC.length), MAGIC)) {
            throw new InvalidGenesisException("bad_magic", "BootstrapGenesis magic is not " + BootstrapGenesis.MAGIC);
        }
        int version = bytes[OFFSET_VERSION] & 0xFF;
        if (version != BootstrapGenesis.VERSION) {
            throw new InvalidGenesisException("unknown_version", "unknown BootstrapGenesis version");
        }
        int suite = bytes[OFFSET_SUITE] & 0xFF;
        if (suite != BootstrapGenesis.SUITE_NONE) {
            throw new InvalidGenesisException("unknown_suite", "unknown BootstrapGenesis suite");
        }
        byte[] entropy = Arrays.copyOfRange(bytes, OFFSET_ENTROPY, BootstrapGenesis.LENGTH);
        return new BootstrapGenesis(version, suite, entropy, bytes);
    }

    public static byte[] encode(byte[] entropy) {
        if (entropy.length != BootstrapGenesis.ENTROPY_LENGTH) {
            throw new IllegalArgumentException("entropy is " + BootstrapGenesis.ENTROPY_LENGTH + " bytes");
        }
        byte[] out = new byte[BootstrapGenesis.LENGTH];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[OFFSET_VERSION] = (byte) BootstrapGenesis.VERSION;
        out[OFFSET_SUITE] = (byte) BootstrapGenesis.SUITE_NONE;
        System.arraycopy(entropy, 0, out, OFFSET_ENTROPY, BootstrapGenesis.ENTROPY_LENGTH);
        return out;
    }

    public static BootstrapGenesis mint() {
        byte[] entropy = new byte[BootstrapGenesis.ENTROPY_LENGTH];
        RANDOM.nextBytes(entropy);
        return decode(encode(entropy));
    }
}
