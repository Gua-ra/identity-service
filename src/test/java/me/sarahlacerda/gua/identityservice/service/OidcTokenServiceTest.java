package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.text.ParseException;
import java.time.Duration;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jwt.SignedJWT;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

class OidcTokenServiceTest {

    private OidcTokenService tokenService;
    private OidcProperties properties;

    @BeforeEach
    void setUp() {
        properties = new OidcProperties();
        properties.setIssuer("https://identity.example.com");
        properties.setJwtSigningSecret("super-secret-signing-key-value-that-is-long");
        properties.setAccessTokenTtl(Duration.ofMinutes(15));
        properties.setIdTokenTtl(Duration.ofMinutes(15));

        tokenService = new OidcTokenService(properties);
    }

    @Test
    void issueTokensProducesSignedJwtWithClaims() throws ParseException {
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
        assertThat(tokens.accessToken()).isNotBlank();
        assertThat(tokens.idToken()).isNotBlank();

        SignedJWT accessJwt = SignedJWT.parse(tokens.accessToken());
        SignedJWT idJwt = SignedJWT.parse(tokens.idToken());

        assertClaims(accessJwt, authorization);
        assertClaims(idJwt, authorization);
    }

    private void assertClaims(SignedJWT jwt, OidcAuthorization authorization) throws ParseException {
        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(properties.getIssuer());
        assertThat(claims.getSubject()).isEqualTo(authorization.userId());
        assertThat(claims.getAudience()).containsExactly(authorization.clientId());
        assertThat(claims.getStringClaim("phone_number")).isEqualTo(authorization.phoneNumber());
        assertThat(claims.getStringClaim("name")).isEqualTo(authorization.displayName());
        assertThat(claims.getStringClaim("scope")).isEqualTo(authorization.scopeAsString());
        assertThat(Duration.between(claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
            .isEqualTo(properties.getAccessTokenTtl());
    }
}
