package me.sarahlacerda.gua.identityservice.config;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Loads the RSA key used to sign OIDC tokens (RS256). If no key material is configured, generates an
 * ephemeral 2048-bit RSA key at startup and logs a WARN — suitable for local dev only.
 */
@Configuration
public class OidcSigningKeyConfig {

    private static final Logger log = LoggerFactory.getLogger(OidcSigningKeyConfig.class);

    @Bean
    public RSAKey oidcSigningKey(OidcProperties properties) {
        OidcProperties.Signing signing = properties.getSigning();

        if (signing.getPrivateKey() == null || signing.getPrivateKey().isBlank()) {
            log.warn("No oidc.signing.private-key configured — generating an ephemeral RSA key for THIS process only. "
                + "Configure OIDC_RSA_PRIVATE_KEY for production.");
            return generateEphemeral(signing.getKeyId());
        }

        try {
            RSAPrivateKey privateKey = readPrivateKey(signing.getPrivateKey());
            RSAPublicKey publicKey = signing.getPublicKey() != null && !signing.getPublicKey().isBlank()
                ? readPublicKey(signing.getPublicKey())
                : derivePublic(privateKey);

            return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(signing.getKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load OIDC signing key", ex);
        }
    }

    @Bean
    public JWKSet oidcPublicJwkSet(RSAKey oidcSigningKey) {
        return new JWKSet(oidcSigningKey.toPublicJWK());
    }

    private static RSAKey generateEphemeral(String keyId) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate())
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA not available", ex);
        }
    }

    private static RSAPrivateKey readPrivateKey(String pem) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] bytes = decodePem(pem, "PRIVATE KEY");
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    private static RSAPublicKey readPublicKey(String pem) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] bytes = decodePem(pem, "PUBLIC KEY");
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    }

    private static RSAPublicKey derivePublic(RSAPrivateKey privateKey) throws Exception {
        java.security.interfaces.RSAPrivateCrtKey crt = (java.security.interfaces.RSAPrivateCrtKey) privateKey;
        java.security.spec.RSAPublicKeySpec spec = new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static byte[] decodePem(String pem, String label) {
        String stripped = pem
            .replace("-----BEGIN " + label + "-----", "")
            .replace("-----END " + label + "-----", "")
            .replaceAll("\\s", "");
        return Base64.getDecoder().decode(stripped);
    }
}
