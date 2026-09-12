package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
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


    /**
     * Loads an Ed25519 private key from base64 PKCS#8, the shape the deployment Secret holds a roster
     * membership key in.
     *
     * @throws IllegalStateException when the value is not a readable Ed25519 private key; the message
     *                               never echoes the value, because the value is key material
     */
    public static PrivateKey privateKeyFromPkcs8(String base64Pkcs8) {
        if (base64Pkcs8 == null || base64Pkcs8.isBlank()) {
            throw new IllegalStateException("no Ed25519 private key is configured");
        }
        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64Pkcs8.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("the configured Ed25519 private key is not base64", ex);
        }
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", ex);
        } catch (InvalidKeySpecException | IllegalArgumentException ex) {
            throw new IllegalStateException("the configured Ed25519 private key is not readable PKCS#8", ex);
        }
    }

    /** Signs {@code message} with an Ed25519 private key. */
    public static byte[] sign(PrivateKey privateKey, byte[] message) {
        try {
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(privateKey);
            signer.update(message);
            return signer.sign();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", ex);
        } catch (InvalidKeyException | SignatureException ex) {
            throw new IllegalStateException("Ed25519 signing failed", ex);
        }
    }

    /**
     * Reads a raw 32-byte Ed25519 public key from base64, accepting either the bare key or an X.509
     * {@code SubjectPublicKeyInfo} wrapper. The roster publishes member keys base64-encoded and the two
     * spellings are both in circulation, so a comparison that understood only one would report a
     * configuration mismatch that is not there.
     *
     * @throws InvalidGenesisException when the value is neither spelling of a curve point
     */
    public static byte[] rawPublicKeyFromBase64(String base64Key, String reason) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new InvalidGenesisException(reason, "Ed25519 public key is missing");
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException ex) {
            throw new InvalidGenesisException(reason, "Ed25519 public key is not base64", ex);
        }
        byte[] raw;
        if (decoded.length == RAW_PUBLIC_KEY_LENGTH) {
            raw = decoded;
        } else if (decoded.length == SPKI_PREFIX.length + RAW_PUBLIC_KEY_LENGTH
                && java.util.Arrays.equals(java.util.Arrays.copyOfRange(decoded, 0, SPKI_PREFIX.length),
                        SPKI_PREFIX)) {
            raw = java.util.Arrays.copyOfRange(decoded, SPKI_PREFIX.length, decoded.length);
        } else {
            throw new InvalidGenesisException(reason, "Ed25519 public key is neither 32 raw bytes nor X.509");
        }
        fromRaw(raw, reason);
        return raw;
    }

    /**
     * Fixed probe the key-pair check signs. It is a compile-time constant with its own domain prefix,
     * never influenced by a caller, and it is neither a placement record (those open with ASCII
     * {@code GUAP}) nor an admission possession proof (that path signs the bare server name). ADM-008
     * decision 7 forbids a membership key from signing <em>caller-chosen</em> bytes, because admission's
     * proof carries no prefix; a constant this service compiles in is not caller-chosen, and the
     * signature it produces is public and useless on its own.
     */
    private static final byte[] KEY_PAIR_PROBE =
            "gua-placement-signing-key-check.v1".getBytes(StandardCharsets.US_ASCII);

    /**
     * True when {@code privateKey} is the private half of {@code rawPublicKey}.
     *
     * <p>Checked by signing the fixed probe above and verifying it under the candidate public key,
     * rather than by deriving the public half: Ed25519 public-key derivation needs curve arithmetic the
     * JDK does not expose, and every alternative would mean a new cryptography dependency. Verifying a
     * signature proves the pair matches just as conclusively.
     */
    public static boolean publicHalfMatches(PrivateKey privateKey, byte[] rawPublicKey) {
        try {
            return verify(rawPublicKey, KEY_PAIR_PROBE, sign(privateKey, KEY_PAIR_PROBE));
        } catch (RuntimeException ex) {
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
