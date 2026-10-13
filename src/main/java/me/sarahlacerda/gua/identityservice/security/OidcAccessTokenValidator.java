package me.sarahlacerda.gua.identityservice.security;

import java.util.Optional;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

@Component
@RequiredArgsConstructor
public class OidcAccessTokenValidator {

    private static final Logger log = LoggerFactory.getLogger(OidcAccessTokenValidator.class);

    private final OidcTokenService oidcTokenService;
    private final OidcClientService clientService;
    private final MatrixAdminClient matrixAdminClient;

    public Optional<OidcAuthenticatedPrincipal> validate(String accessToken) {
        Optional<OidcAuthenticatedPrincipal> principal = oidcTokenService.parseAccessToken(accessToken);
        if (principal.isPresent()) {
            // A token this service minted authenticates the bearer API only when its client is
            // registered with api-access. A relying party's token is valid at /userinfo alone and
            // never falls through to whoami, which could not know it.
            if (clientService.grantsApiAccess(principal.get().clientId())) {
                return principal;
            }
            log.debug("Access token issued to a client without API access was refused");
            return Optional.empty();
        }
        // Fall back to the homeserver's whoami for a Matrix-issued access token (MAS or Synapse
        // password login), so the apps can reuse their SDK session token on the bearer API.
        Optional<String> matrixUserId = matrixAdminClient.whoami(accessToken);
        if (matrixUserId.isPresent()) {
            return Optional.of(new OidcAuthenticatedPrincipal(matrixUserId.get(), null, null, Set.of()));
        }
        log.debug("Access token validation failed for both OIDC and Matrix paths");
        return Optional.empty();
    }
}
