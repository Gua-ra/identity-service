package me.sarahlacerda.gua.identityservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

class OidcAccessTokenValidatorTest {

    private OidcTokenService tokenService;
    private OidcClientService clientService;
    private MatrixAdminClient matrixAdminClient;
    private OidcAccessTokenValidator validator;

    @BeforeEach
    void setUp() {
        tokenService = mock(OidcTokenService.class);
        clientService = mock(OidcClientService.class);
        matrixAdminClient = mock(MatrixAdminClient.class);
        when(clientService.grantsApiAccess("gua-ios")).thenReturn(true);
        validator = new OidcAccessTokenValidator(tokenService, clientService, matrixAdminClient);
    }

    @Test
    void validateReturnsPrincipalWhenTokenValid() {
        OidcAuthenticatedPrincipal principal = principalIssuedTo("gua-ios");
        when(tokenService.parseAccessToken("token")).thenReturn(Optional.of(principal));

        Optional<OidcAuthenticatedPrincipal> result = validator.validate("token");

        assertThat(result).contains(principal);
        verify(tokenService).parseAccessToken("token");
    }

    @Test
    void validateRefusesAServiceTokenIssuedToAClientWithoutApiAccess() {
        when(tokenService.parseAccessToken("mas-token")).thenReturn(Optional.of(principalIssuedTo("mas")));

        Optional<OidcAuthenticatedPrincipal> result = validator.validate("mas-token");

        assertThat(result).isEmpty();
        verify(matrixAdminClient, never()).whoami(any());
    }

    @Test
    void validateRefusesAServiceTokenNamingNoClient() {
        OidcAuthenticatedPrincipal noClient = new OidcAuthenticatedPrincipal("@user:domain", null, null,
                Set.of("openid"));
        when(tokenService.parseAccessToken("token")).thenReturn(Optional.of(noClient));

        assertThat(validator.validate("token")).isEmpty();
        verify(matrixAdminClient, never()).whoami(any());
    }

    @Test
    void validateFallsBackToMatrixWhoamiWhenOidcParseFails() {
        when(tokenService.parseAccessToken("matrix-token")).thenReturn(Optional.empty());
        when(matrixAdminClient.whoami("matrix-token")).thenReturn(Optional.of("@john:dev.local"));

        Optional<OidcAuthenticatedPrincipal> result = validator.validate("matrix-token");

        assertThat(result).isPresent();
        assertThat(result.get().userId()).isEqualTo("@john:dev.local");
        assertThat(result.get().clientId()).isNull();
    }

    @Test
    void validateReturnsEmptyWhenBothPathsFail() {
        when(tokenService.parseAccessToken("invalid")).thenReturn(Optional.empty());
        when(matrixAdminClient.whoami("invalid")).thenReturn(Optional.empty());

        Optional<OidcAuthenticatedPrincipal> result = validator.validate("invalid");

        assertThat(result).isEmpty();
    }

    private static OidcAuthenticatedPrincipal principalIssuedTo(String clientId) {
        return new OidcAuthenticatedPrincipal("@user:domain", "+15555551212", "User", null, Set.of("openid"),
                clientId);
    }
}
