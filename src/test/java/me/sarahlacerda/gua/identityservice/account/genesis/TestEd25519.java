package me.sarahlacerda.gua.identityservice.account.genesis;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Arrays;

/**
 * Throwaway Ed25519 keys, minted in memory for the duration of one test. Nothing here reads a key from
 * a cluster, a secret or a file: a test that needs a signature generates the pair it signs with.
 */
public final class TestEd25519 {

    private TestEd25519() {
    }

    public record Pair(byte[] rawPublicKey, PrivateKey privateKey) {
    }

    public static Pair generate() {
        try {
            KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            byte[] spki = pair.getPublic().getEncoded();
            // The X.509 SubjectPublicKeyInfo wrapper is a fixed 12-byte prefix; the key is the tail.
            byte[] raw = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
            return new Pair(raw, pair.getPrivate());
        } catch (Exception ex) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", ex);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
            signature.update(message);
            return signature.sign();
        } catch (Exception ex) {
            throw new IllegalStateException("Ed25519 signing failed", ex);
        }
    }
}
