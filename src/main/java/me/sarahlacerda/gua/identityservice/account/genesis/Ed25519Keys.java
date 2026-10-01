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

public final class Ed25519Keys {

    public static final int RAW_PUBLIC_KEY_LENGTH = 32;
    public static final int SIGNATURE_LENGTH = 64;

    private static final String ALGORITHM = "Ed25519";
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private Ed25519Keys() {
    }

    /** KeyFactory only parses the encoding. Initializing a verifier forces the curve-point check. */
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

    public static boolean isOnCurve(byte[] rawPublicKey) {
        try {
            fromRaw(rawPublicKey, "invalid_key");
            return true;
        } catch (InvalidGenesisException ex) {
            return false;
        }
    }

    /** Returns false on malformed input, so a bad key and a bad signature look the same to the caller. */
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


    /** The exception message never includes the value, which is key material. */
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

    /** Accepts the bare 32-byte key or its X.509 SubjectPublicKeyInfo wrapper. */
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

    /** Fixed probe with its own domain prefix. A membership key must never sign caller-chosen bytes. */
    private static final byte[] KEY_PAIR_PROBE =
            "gua-placement-signing-key-check.v1".getBytes(StandardCharsets.US_ASCII);

    /** Signs the fixed probe and verifies it, because the JDK does not expose Ed25519 public-key derivation. */
    public static boolean publicHalfMatches(PrivateKey privateKey, byte[] rawPublicKey) {
        try {
            return verify(rawPublicKey, KEY_PAIR_PROBE, sign(privateKey, KEY_PAIR_PROBE));
        } catch (RuntimeException ex) {
            return false;
        }
    }

    /** The all-zero encoding decodes to a valid low-order point, so it is refused separately. */
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
