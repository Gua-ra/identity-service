package me.sarahlacerda.gua.identityservice.account.genesis;

/** RFC 4648 base32, lowercase and unpadded. Decoding is strict so each byte string has exactly one spelling. */
public final class Base32 {

    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

    private static final int[] VALUES = new int[128];

    static {
        java.util.Arrays.fill(VALUES, -1);
        for (int i = 0; i < ALPHABET.length(); i++) {
            VALUES[ALPHABET.charAt(i)] = i;
        }
    }

    private Base32() {
    }

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
            out.append(ALPHABET.charAt((buffer << (5 - bits)) & 0x1F));
        }
        return out.toString();
    }

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
        if (bits > 0 && (buffer & ((1 << bits) - 1)) != 0) {
            throw new InvalidGenesisException("bad_base32", "base32 value has non-zero trailing bits");
        }
        return out;
    }
}
