package me.sarahlacerda.gua.identityservice.security;

import java.util.Optional;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

@Component
@RequiredArgsConstructor
public class OidcAccessTokenValidator {

    private static final Logger log = LoggerFactory.getLogger(OidcAccessTokenValidator.class);

    private final OidcTokenService oidcTokenService;
    private final MatrixAdminClient matrixAdminClient;

    public Optional<OidcAuthenticatedPrincipal> validate(String accessToken) {
        Optional<OidcAuthenticatedPrincipal> principal = oidcTokenService.parseAccessToken(accessToken);
        if (principal.isPresent()) {
            return principal;
        }
        // Fall back to validating Matrix-issued access tokens (MAS or Synapse password
        // login)
        // via the homeserver's whoami endpoint. This lets the iOS app reuse its
        // existing SDK
        // access token for our authenticated endpoints (e.g. /account/reauth/*).
        Optional<String> matrixUserId = matrixAdminClient.whoami(accessToken);
        if (matrixUserId.isPresent()) {
            return Optional.of(new OidcAuthenticatedPrincipal(matrixUserId.get(), null, null, Set.of()));
        }
        log.debug("Access token validation failed for both OIDC and Matrix paths");
        return Optional.empty();
    }
}
