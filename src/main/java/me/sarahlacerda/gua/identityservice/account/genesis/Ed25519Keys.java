package me.sarahlacerda.gua.identityservice.account.genesis;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

/**
 * Raw RFC 8032 Ed25519 public keys, as the genesis objects carry them, on top of the JDK-native Ed25519
 * provider (JDK 15+). No new dependency: the account objects store the bare 32-byte key, and the JDK
 * KeyFactory wants X.509 {@code SubjectPublicKeyInfo}, so the fixed 12-byte SPKI prefix is prepended here.
 *
 * <p>{@link #isOnCurve(byte[])} is what backs ADM-008 decision 1's "a key failing Ed25519 point decoding"
 * rule. It is deliberately separate from the all-zero check: the all-zero encoding decodes to a valid
 * low-order point, so point decoding alone would let it through, which is exactly why ADM-008 lists the
 * two rules separately.
 */
public final class Ed25519Keys {

    public static final int RAW_PUBLIC_KEY_LENGTH = 32;
    public static final int SIGNATURE_LENGTH = 64;

    private static final String ALGORITHM = "Ed25519";
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private Ed25519Keys() {
    }

    /**
     * Turns a raw 32-byte Ed25519 public key into a JDK {@link PublicKey}, and checks that it really is
     * a curve point.
     *
     * <p>The point check is deliberately not left to {@link KeyFactory}. On this JVM
     * {@code generatePublic} only parses the encoding: it accepts a y coordinate larger than the field
     * prime and one that is not on the curve, and defers both checks to the first
     * {@link Signature#initVerify}. ADM-008 decision 1 requires the decoder itself to refuse such a key,
     * so the verifier is initialized here, where the JVM performs the decoding, and the resulting
     * {@code InvalidKeyException} is turned into a decode failure.
     *
     * @throws InvalidGenesisException with the given reason when the bytes are not a curve point
     */
    public static PublicKey fromRaw(byte[] rawPublicKey, String reason) {
        if (rawPublicKey == null || rawPublicKey.length != RAW_PUBLIC_KEY_LENGTH) {
            throw new InvalidGenesisException(reason, "Ed25519 public key is not " + RAW_PUBLIC_KEY_LENGTH + " bytes");
        }
        byte[] spki = new byte[SPKI_PREFIX.length + RAW_PUBLIC_KEY_LENGTH];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(rawPublicKey, 0, spki, SPKI_PREFIX.length, RAW_PUBLIC_KEY_LENGTH);
        PublicKey key;
        try {
            key = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(spki));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", ex);
        } catch (InvalidKeySpecException | IllegalArgumentException ex) {
            throw new InvalidGenesisException(reason, "Ed25519 public key does not parse", ex);
        }
        try {
            Signature.getInstance(ALGORITHM).initVerify(key);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", ex);
        } catch (InvalidKeyException ex) {
            throw new InvalidGenesisException(reason, "Ed25519 public key does not decode to a curve point", ex);
        }
        return key;
    }

    /** True when the raw bytes decode to an Ed25519 curve point. */
    public static boolean isOnCurve(byte[] rawPublicKey) {
        try {
            fromRaw(rawPublicKey, "invalid_key");
            return true;
        } catch (InvalidGenesisException ex) {
            return false;
        }
    }

    /**
     * Verifies a detached Ed25519 signature over {@code message}. Returns false for any malformed input
     * rather than throwing, so a caller cannot tell a bad key from a bad signature by the exception type.
     */
    public static boolean verify(byte[] rawPublicKey, byte[] message, byte[] signature) {
        if (rawPublicKey == null || message == null || signature == null) {
            return false;
        }
        if (signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        PublicKey key;
        try {
            key = fromRaw(rawPublicKey, "invalid_key");
        } catch (InvalidGenesisException ex) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", ex);
        } catch (InvalidKeyException | SignatureException ex) {
            return false;
        }
    }

    /** True when every byte is zero. ADM-008 decision 1 refuses such a key even though it decodes. */
    public static boolean isAllZero(byte[] value) {
        if (value == null) {
            return true;
        }
        int accumulator = 0;
        for (byte b : value) {
            accumulator |= b;
        }
        return accumulator == 0;
    }
}
