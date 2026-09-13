package me.sarahlacerda.gua.identityservice.service;

import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.config.OidcSigningKeyConfig;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;
import me.sarahlacerda.gua.identityservice.service.security.EndOtherSessionsService;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * ADM-001 S6 and ADM-008 decision 10: Phase 3 changes no OIDC subject semantics.
 *
 * <p>{@code sub} stays the Matrix user id, {@code preferred_username} stays the handle stored in the
 * directory, and no claim carries an accountId. The last one is load-bearing rather than cosmetic: MAS
 * derives the Matrix localpart from an arbitrary template over the imported claims, and an accountId is
 * lowercase letters and digits, so it would pass MAS's localpart rules. A claim carrying one would be a
 * single config line away from re-keying every account onto it.
 */
class OidcSubjectUnchangedTest {

    private static final String MXID = "@alice:example.org";
    private static final Pattern ACCOUNT_ID = Pattern.compile(AccountId.CANONICAL_PATTERN);

    private OidcTokenService tokenService;

    @BeforeEach
    void setUp() {
        OidcProperties properties = new OidcProperties();
        properties.setIssuer("https://identity.example.com");
        properties.setAccessTokenTtl(Duration.ofMinutes(15));
        properties.setIdTokenTtl(Duration.ofMinutes(15));
        properties.getSigning().setKeyId("test-key-id");
        properties.setClients(List.of(client("mas")));

        RSAKey signingKey = new OidcSigningKeyConfig().oidcSigningKey(properties);
        tokenService = new OidcTokenService(properties, signingKey, mock(TokenRevocationService.class),
                mock(EndOtherSessionsService.class));
    }

    private static OidcProperties.ClientRegistration client(String clientId) {
        OidcProperties.ClientRegistration registration = new OidcProperties.ClientRegistration();
        registration.setClientId(clientId);
        return registration;
    }

    private OidcTokenResponse issue(String preferredUsername) {
        return tokenService.issueTokens(new OidcAuthorization(
                MXID, "+15551234567", "Alice", preferredUsername,
                Set.of("openid", "profile", "phone"), "mas", "nonce-1"));
    }

    @Test
    void theSubjectIsStillTheMatrixUserId() throws ParseException {
        OidcTokenResponse tokens = issue("alice");

        for (String token : List.of(tokens.accessToken(), tokens.idToken())) {
            assertThat(SignedJWT.parse(token).getJWTClaimsSet().getSubject()).isEqualTo(MXID);
        }
    }

    @Test
    void preferredUsernameIsStillTheStoredHandle() throws ParseException {
        OidcTokenResponse tokens = issue("alice");

        assertThat(SignedJWT.parse(tokens.idToken()).getJWTClaimsSet().getStringClaim("preferred_username"))
                .isEqualTo("alice");
    }

    @Test
    void noClaimInEitherTokenCarriesAnAccountId() throws ParseException {
        OidcTokenResponse tokens = issue("alice");

        for (String token : List.of(tokens.accessToken(), tokens.idToken())) {
            Map<String, Object> claims = SignedJWT.parse(token).getJWTClaimsSet().getClaims();
            for (Map.Entry<String, Object> claim : claims.entrySet()) {
                assertThat(claim.getKey()).isNotIn("account_id", "accountId", "genesis");
                if (claim.getValue() != null) {
                    assertThat(ACCOUNT_ID.matcher(String.valueOf(claim.getValue())).matches())
                            .as("claim %s must not be an accountId", claim.getKey())
                            .isFalse();
                }
            }
        }
    }

    @Test
    void theClaimSetIsExactlyTheOneItWasBeforeGenesisExisted() throws ParseException {
        OidcTokenResponse tokens = issue("alice");

        assertThat(SignedJWT.parse(tokens.idToken()).getJWTClaimsSet().getClaims().keySet())
                .containsExactlyInAnyOrder("iss", "sub", "aud", "exp", "iat", "jti", "scope",
                        "phone_number", "name", "preferred_username", "nonce");
    }

    @Test
    void theGuardPatternWouldActuallyCatchAnAccountId() {
        // Guards that cannot fail are worthless: this shows the pattern used above matches a real id.
        assertThat(ACCOUNT_ID.matcher(
                AccountId.derive(AccountId.CLASS_GENESIS, "bytes".getBytes()).value()).matches()).isTrue();
    }
}
