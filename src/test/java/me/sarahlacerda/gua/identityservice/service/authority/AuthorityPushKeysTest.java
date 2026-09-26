// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Both shapes an operator can actually hand this service, because only one of them used to work.
 *
 * <p>The documented contract is base64 of PKCS#8 DER. What Apple and Google hand over is PEM: a {@code .p8}
 * file and the {@code private_key} field of a service-account JSON. Base64 either of those and the decoded
 * bytes begin with the armour line, which is not a key. That is how dev ended up with two transports that
 * counted as channels and could not sign, and the first ADOPT_ROOT went pending with nobody told.
 */
class AuthorityPushKeysTest {

    @Test
    void baseSixtyFourOfDerLoads() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        String der = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        PrivateKey loaded = AuthorityPushKeys.load("EC", der);

        assertThat(loaded.getEncoded()).isEqualTo(pair.getPrivate().getEncoded());
    }

    @Test
    void baseSixtyFourOfTheWholePemFileLoadsToo() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String pem = pem(pair.getPrivate().getEncoded());
        String configured = Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII));

        PrivateKey loaded = AuthorityPushKeys.load("RSA", configured);

        assertThat(loaded.getEncoded()).isEqualTo(pair.getPrivate().getEncoded());
    }

    @Test
    void whitespaceAndWrappingDoNotMatter() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        String der = Base64.getMimeEncoder().encodeToString(pair.getPrivate().getEncoded());

        assertThat(AuthorityPushKeys.load("EC", der).getEncoded()).isEqualTo(pair.getPrivate().getEncoded());
    }

    @Test
    void anEmptyValueIsRefused() {
        assertThatThrownBy(() -> AuthorityPushKeys.load("EC", "  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no key is configured");
    }

    @Test
    void armourWithNoBodyIsRefused() {
        String empty = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n";
        String configured = Base64.getEncoder().encodeToString(empty.getBytes(StandardCharsets.US_ASCII));

        assertThatThrownBy(() -> AuthorityPushKeys.load("RSA", configured))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no body");
    }

    @Test
    void theWrongAlgorithmIsRefusedAndTheMessageCarriesNoKeyMaterial() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        String der = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        assertThatThrownBy(() -> AuthorityPushKeys.load("RSA", der))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not PKCS#8")
                .hasMessageNotContaining(der.substring(0, 16));
    }

    private static String pem(byte[] der) {
        StringBuilder out = new StringBuilder("-----BEGIN PRIVATE KEY-----\n");
        String body = Base64.getEncoder().encodeToString(der);
        for (int i = 0; i < body.length(); i += 64) {
            out.append(body, i, Math.min(i + 64, body.length())).append('\n');
        }
        return out.append("-----END PRIVATE KEY-----\n").toString();
    }
}
