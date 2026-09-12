package me.sarahlacerda.gua.identityservice.account.genesis;

/**
 * RFC 4648 base32, lowercase and unpadded, which is the spelling ADM-008 fixes for an accountId.
 *
 * <p>The decoder is strict in both directions an ambiguity could enter: it accepts only the lowercase
 * alphabet (no uppercase, no padding, no RFC 4648 section 6 "extended hex" alphabet), only a character
 * count that an unpadded encoding can actually produce, and only trailing bits that are zero. Those are
 * the three ways a decoder that "helpfully" accepts more would give one byte string several spellings,
 * which ADM-001 L4 forbids for anything a signature or a permanent identifier covers.
 */
public final class Base32 {

    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

    /** Reverse lookup, -1 for every character outside the alphabet. */
    private static final int[] VALUES = new int[128];

    static {
        java.util.Arrays.fill(VALUES, -1);
        for (int i = 0; i < ALPHABET.length(); i++) {
            VALUES[ALPHABET.charAt(i)] = i;
        }
    }

    private Base32() {
    }

    /** Encodes {@code data} as lowercase unpadded base32. */
    public static String encode(byte[] data) {
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                out.append(ALPHABET.charAt((buffer >>> (bits - 5)) & 0x1F));
                bits -= 5;
            }
        }
        if (bits > 0) {
            // Left-over bits are left-aligned and zero-padded on the right.
            out.append(ALPHABET.charAt((buffer << (5 - bits)) & 0x1F));
        }
        return out.toString();
    }

    /**
     * Decodes lowercase unpadded base32.
     *
     * @throws InvalidGenesisException with reason {@code bad_base32} on any character outside the
     *                                 alphabet, a character count no unpadded encoding produces, or
     *                                 non-zero trailing bits
     */
    public static byte[] decode(String encoded) {
        if (encoded == null) {
            throw new InvalidGenesisException("bad_base32", "base32 value is missing");
        }
        int remainder = encoded.length() % 8;
        // 1, 3 and 6 left-over characters cannot come out of any byte string.
        if (remainder == 1 || remainder == 3 || remainder == 6) {
            throw new InvalidGenesisException("bad_base32", "base32 length is not a valid unpadded length");
        }

        int outputLength = encoded.length() * 5 / 8;
        byte[] out = new byte[outputLength];
        int buffer = 0;
        int bits = 0;
        int index = 0;
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            int value = c < VALUES.length ? VALUES[c] : -1;
            if (value < 0) {
                throw new InvalidGenesisException("bad_base32", "base32 value has a character outside the alphabet");
            }
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                out[index++] = (byte) ((buffer >>> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        // Whatever is left over is padding and must be zero, or one byte string has several spellings.
        if (bits > 0 && (buffer & ((1 << bits) - 1)) != 0) {
            throw new InvalidGenesisException("bad_base32", "base32 value has non-zero trailing bits");
        }
        return out;
    }
}
