package me.sarahlacerda.gua.identityservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

class OidcAccessTokenValidatorTest {

    private OidcTokenService tokenService;
    private MatrixAdminClient matrixAdminClient;
    private OidcAccessTokenValidator validator;

    @BeforeEach
    void setUp() {
        tokenService = mock(OidcTokenService.class);
        matrixAdminClient = mock(MatrixAdminClient.class);
        validator = new OidcAccessTokenValidator(tokenService, matrixAdminClient);
    }

    @Test
    void validateReturnsPrincipalWhenTokenValid() {
        OidcAuthenticatedPrincipal principal = new OidcAuthenticatedPrincipal("@user:domain", "+15555551212", "User",
                Set.of("openid"));
        when(tokenService.parseAccessToken("token")).thenReturn(Optional.of(principal));

        Optional<OidcAuthenticatedPrincipal> result = validator.validate("token");

        assertThat(result).contains(principal);
        verify(tokenService).parseAccessToken("token");
    }

    @Test
    void validateFallsBackToMatrixWhoamiWhenOidcParseFails() {
        when(tokenService.parseAccessToken("matrix-token")).thenReturn(Optional.empty());
        when(matrixAdminClient.whoami("matrix-token")).thenReturn(Optional.of("@john:dev.local"));

        Optional<OidcAuthenticatedPrincipal> result = validator.validate("matrix-token");

        assertThat(result).isPresent();
        assertThat(result.get().userId()).isEqualTo("@john:dev.local");
    }

    @Test
    void validateReturnsEmptyWhenBothPathsFail() {
        when(tokenService.parseAccessToken("invalid")).thenReturn(Optional.empty());
        when(matrixAdminClient.whoami("invalid")).thenReturn(Optional.empty());

        Optional<OidcAuthenticatedPrincipal> result = validator.validate("invalid");

        assertThat(result).isEmpty();
    }
}
