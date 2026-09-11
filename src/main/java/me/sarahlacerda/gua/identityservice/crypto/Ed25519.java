package me.sarahlacerda.gua.identityservice.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Minimal JDK-native Ed25519 (JDK 15+) for signing this homeserver's directory-write requests with its
 * membership credential: the Ed25519 key the gua-resolver admitted for this homeserver. The resolver
 * verifies the signature against that roster entry, which proves which member wrote the row and nothing
 * more: any ACTIVE member key is accepted for any row, so the signature does not show that the row is
 * legitimately that member's own account. This is the write path
 * <a href="https://github.com/Gua-ra/gua-resolver/blob/main/docs/decisions/ADM-001-identifier-binding-placement-trust.md">ADM-001</a> L1b removes.
 *
 * <p>Private key is the base64 PKCS#8 form (matches `openssl genpkey -algorithm ed25519 -outform DER`).
 */
public final class Ed25519 {

    private static final String ALG = "Ed25519";

    private Ed25519() {}

    public static PrivateKey privateKey(String base64Pkcs8) {
        try {
            byte[] der = Base64.getDecoder().decode(base64Pkcs8);
            return KeyFactory.getInstance(ALG).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid Ed25519 private key", e);
        }
    }

    /** Sign {@code message}, returning the detached signature base64-encoded. */
    public static String sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initSign(key);
            s.update(message);
            return Base64.getEncoder().encodeToString(s.sign());
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }
}
