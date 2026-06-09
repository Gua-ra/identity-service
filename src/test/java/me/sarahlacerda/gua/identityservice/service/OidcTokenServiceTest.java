package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.config.OidcSigningKeyConfig;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;

class OidcTokenServiceTest {

    private OidcTokenService tokenService;
    private OidcProperties properties;
    private RSAKey signingKey;
    private TokenRevocationService tokenRevocationService;

    @BeforeEach
    void setUp() {
        properties = new OidcProperties();
        properties.setIssuer("https://identity.example.com");
        properties.setAccessTokenTtl(Duration.ofMinutes(15));
        properties.setIdTokenTtl(Duration.ofMinutes(15));
        properties.getSigning().setKeyId("test-key-id");
        properties.setClients(List.of(client("mas"), client("gua-ios")));

        signingKey = new OidcSigningKeyConfig().oidcSigningKey(properties);
        tokenRevocationService = mock(TokenRevocationService.class);
        tokenService = new OidcTokenService(properties, signingKey, tokenRevocationService);
    }

    private static OidcProperties.ClientRegistration client(String clientId) {
        OidcProperties.ClientRegistration registration = new OidcProperties.ClientRegistration();
        registration.setClientId(clientId);
        return registration;
    }

    @Test
    void issueTokensProducesRs256SignedJwtWithClaims() throws ParseException {
        OidcAuthorization authorization = new OidcAuthorization(
            "user-123",
            "+15551234567",
            "Alice",
            Set.of("openid", "profile"),
            "mas"
        );

        OidcTokenResponse tokens = tokenService.issueTokens(authorization);

        assertThat(tokens.tokenType()).isEqualTo("Bearer");
        assertThat(tokens.expiresIn()).isEqualTo(properties.getAccessTokenTtl().toSeconds());
        assertThat(tokens.scope()).isEqualTo("openid profile");

        SignedJWT accessJwt = SignedJWT.parse(tokens.accessToken());
        assertThat(accessJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(accessJwt.getHeader().getKeyID()).isEqualTo("test-key-id");
        assertClaims(accessJwt, authorization);
        assertClaims(SignedJWT.parse(tokens.idToken()), authorization);
    }

    @Test
    void parseAccessTokenRoundTrips() {
        OidcAuthorization authorization = new OidcAuthorization(
            "user-99", "+15550009999", null, Set.of("openid"), "gua-ios"
        );
        OidcTokenResponse tokens = tokenService.issueTokens(authorization);

        OidcAuthenticatedPrincipal principal = tokenService.parseAccessToken(tokens.accessToken()).orElseThrow();
        assertThat(principal.userId()).isEqualTo("user-99");
        assertThat(principal.phoneNumber()).isEqualTo("+15550009999");
        assertThat(principal.scope()).containsExactly("openid");
    }

    @Test
    void parseAccessTokenRejectsTamperedSignature() {
        OidcAuthorization authorization = new OidcAuthorization(
            "user-99", "+15550009999", null, Set.of("openid"), "gua-ios"
        );
        String token = tokenService.issueTokens(authorization).accessToken();
        // Flip a few characters in the signature segment.
        int lastDot = token.lastIndexOf('.');
        String tampered = token.substring(0, lastDot + 1) + (token.charAt(lastDot + 1) == 'A' ? "B" : "A")
            + token.substring(lastDot + 2);

        assertThat(tokenService.parseAccessToken(tampered)).isEmpty();
    }

    @Test
    void parseAccessTokenRejectsExpiredToken() throws Exception {
        // Build a token with an expiration in the past, signed with the real key.
        SignedJWT expired = signTestToken(builder -> builder
            .issuer(properties.getIssuer())
            .subject("user-1")
            .audience("mas")
            .expirationTime(Date.from(java.time.Instant.now().minusSeconds(60)))
            .claim("scope", "openid")
            .claim("phone_number", "+15550000000"));

        assertThat(tokenService.parseAccessToken(expired.serialize())).isEmpty();
    }

    @Test
    void parseAccessTokenRejectsWrongIssuer() throws Exception {
        SignedJWT wrongIssuer = signTestToken(builder -> builder
            .issuer("https://attacker.example.com")
            .subject("user-1")
            .audience("mas")
            .expirationTime(Date.from(java.time.Instant.now().plusSeconds(60)))
            .claim("scope", "openid")
            .claim("phone_number", "+15550000000"));

        assertThat(tokenService.parseAccessToken(wrongIssuer.serialize())).isEmpty();
    }

    @Test
    void parseAccessTokenRejectsHs256Algorithm() throws Exception {
        // Token signed by a different RSA key — verifier should reject.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair other = gen.generateKeyPair();
        RSAKey otherKey = new RSAKey.Builder((RSAPublicKey) other.getPublic())
            .privateKey((RSAPrivateKey) other.getPrivate())
            .keyID("other")
            .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer(properties.getIssuer())
            .subject("user-x")
            .audience("mas")
            .expirationTime(Date.from(java.time.Instant.now().plusSeconds(60)))
            .claim("scope", "openid")
            .claim("phone_number", "+15550000000")
            .build();
        SignedJWT signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("other").build(), claims);
        signed.sign(new RSASSASigner(otherKey.toRSAPrivateKey()));

        assertThat(tokenService.parseAccessToken(signed.serialize())).isEmpty();
    }

    @Test
    void parseAccessTokenRejectsUnknownAudience() throws Exception {
        SignedJWT unknownAudience = signTestToken(builder -> builder
            .issuer(properties.getIssuer())
            .subject("user-1")
            .audience("some-other-app")
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
            .claim("scope", "openid")
            .claim("phone_number", "+15550000000"));

        assertThat(tokenService.parseAccessToken(unknownAudience.serialize())).isEmpty();
    }

    @Test
    void parseAccessTokenRejectsMissingAudience() throws Exception {
        SignedJWT noAudience = signTestToken(builder -> builder
            .issuer(properties.getIssuer())
            .subject("user-1")
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
            .claim("scope", "openid")
            .claim("phone_number", "+15550000000"));

        assertThat(tokenService.parseAccessToken(noAudience.serialize())).isEmpty();
    }

    @Test
    void parseAccessTokenRejectsRevokedToken() {
        OidcAuthorization authorization = new OidcAuthorization(
            "user-99", "+15550009999", null, Set.of("openid"), "gua-ios"
        );
        OidcTokenResponse tokens = tokenService.issueTokens(authorization);
        when(tokenRevocationService.isRevoked(eq("user-99"), any())).thenReturn(true);

        assertThat(tokenService.parseAccessToken(tokens.accessToken())).isEmpty();
    }

    @Test
    void publicJwkSetContainsRsaPublicKey() {
        JWKSet publicSet = new OidcSigningKeyConfig().oidcPublicJwkSet(signingKey);
        assertThat(publicSet.getKeys()).hasSize(1);
        assertThat(publicSet.getKeys().get(0).isPrivate()).isFalse();
        assertThat(publicSet.getKeys().get(0).getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    private SignedJWT signTestToken(java.util.function.Consumer<JWTClaimsSet.Builder> claimsCustomizer) throws JOSEException {
        JWTClaimsSet.Builder b = new JWTClaimsSet.Builder();
        claimsCustomizer.accept(b);
        SignedJWT signed = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
            b.build()
        );
        signed.sign(new RSASSASigner(signingKey.toRSAPrivateKey()));
        return signed;
    }

    private void assertClaims(SignedJWT jwt, OidcAuthorization authorization) throws ParseException {
        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(properties.getIssuer());
        assertThat(claims.getSubject()).isEqualTo(authorization.userId());
        assertThat(claims.getAudience()).containsExactly(authorization.clientId());
        assertThat(claims.getStringClaim("phone_number")).isEqualTo(authorization.phoneNumber());
        if (authorization.displayName() != null) {
            assertThat(claims.getStringClaim("name")).isEqualTo(authorization.displayName());
        }
        assertThat(claims.getStringClaim("scope")).isEqualTo(authorization.scopeAsString());
        assertThat(Duration.between(claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
            .isEqualTo(properties.getAccessTokenTtl());
    }
}
