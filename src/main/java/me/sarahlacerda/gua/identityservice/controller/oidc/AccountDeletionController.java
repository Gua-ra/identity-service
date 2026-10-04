package me.sarahlacerda.gua.identityservice.controller.oidc;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.controller.RestExceptionHandler.ErrorResponse;
import me.sarahlacerda.gua.identityservice.domain.Homeserver;
import me.sarahlacerda.gua.identityservice.domain.MatrixIds;
import me.sarahlacerda.gua.identityservice.exception.OidcClientAuthenticationException;
import me.sarahlacerda.gua.identityservice.exception.OidcInvalidRequestException;
import me.sarahlacerda.gua.identityservice.service.account.AccountDeletionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService.RegisteredClient;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;

/**
 * The authentication service's notice that it has deleted an account. The caller proves itself with the
 * confidential client credentials it already presents at {@code /oauth2/token}; a public client holds no
 * secret and is refused. The subject is the {@code sub} this provider issued, which is the account's
 * Matrix user id on one of this deployment's homeservers, and the client may only report accounts on the
 * homeservers its registration lists.
 *
 * <p>Nothing is read or deleted while {@code oidc.account-deletion-notices-enabled} is off.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "OIDC Authorization", description = "OAuth 2.0 authorization code endpoints backing the Matrix Authentication Service")
public class AccountDeletionController {

    private static final Logger log = LoggerFactory.getLogger(AccountDeletionController.class);

    /** The longest Matrix user id the specification allows. */
    private static final int MAX_USER_ID_LENGTH = 255;

    private final OidcProperties oidcProperties;
    private final OidcClientService clientService;
    private final AccountDeletionService accountDeletionService;
    private final HomeserverRegistry homeserverRegistry;

    @PostMapping(value = "/oauth2/account-deleted", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Report an account the authentication service has deleted", description = "Called by the authentication service after it deletes an account. Authenticated as a confidential OIDC client with client_secret_basic or client_secret_post, which may only report accounts on the homeservers its registration lists. Deletes the account's directory entries, security record, passkeys and trusted devices in one transaction, keeps a tombstone that reserves its username for good, then revokes its access tokens and drops its Redis state. Idempotent: 204 whether or not anything was stored. Answers 503 to everyone while the deployment has the notice turned off.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Deleted, or nothing was stored for the account"),
            @ApiResponse(responseCode = "400", description = "sub is missing, malformed, or not on one of this deployment's homeservers", content = @Content),
            @ApiResponse(responseCode = "401", description = "Missing, unknown, public or wrongly authenticated client", content = @Content),
            @ApiResponse(responseCode = "403", description = "The client may not report accounts on the sub's homeserver", content = @Content),
            @ApiResponse(responseCode = "429", description = "Rate limited", content = @Content),
            @ApiResponse(responseCode = "503", description = "Account deletion notices are turned off on this deployment", content = @Content)
    })
    public ResponseEntity<?> accountDeleted(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @Parameter(description = "Client identifier, for client_secret_post.") @RequestParam(value = "client_id", required = false) String clientIdParam,
            @Parameter(description = "Client secret, for client_secret_post.") @RequestParam(value = "client_secret", required = false) String clientSecretParam,
            @Parameter(description = "The sub this provider issued for the deleted account.", required = true) @RequestParam(value = "sub", required = false) String subject,
            HttpServletRequest request) {
        if (!oidcProperties.isAccountDeletionNoticesEnabled()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(new ErrorResponse("account_deletion_notices_disabled",
                            "Account deletion notices are turned off on this deployment"));
        }

        OidcClientCredentials credentials = OidcClientCredentials.resolve(authorizationHeader, clientIdParam,
                clientSecretParam);
        RegisteredClient client;
        try {
            client = clientService.authenticateConfidentialClient(credentials.clientId(), credentials.clientSecret());
        } catch (OidcClientAuthenticationException ex) {
            log.warn("Refused an account deletion notice from {}: client authentication failed", request.getRemoteAddr());
            throw ex;
        }

        Homeserver homeserver = localHomeserverOf(subject).orElseThrow(() -> {
            log.warn("Refused an account deletion notice from client {}: sub is not a user id on this deployment",
                    client.clientId());
            return new OidcInvalidRequestException("invalid_request",
                    "sub must be a user id on one of this deployment's homeservers");
        });
        if (!client.homeserverIds().contains(homeserver.id())) {
            log.warn("Refused an account deletion notice from client {}: it may not report accounts on homeserver {}",
                    client.clientId(), homeserver.id());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("unauthorized_client",
                            "This client may not report accounts on that homeserver"));
        }

        accountDeletionService.delete(subject);
        return ResponseEntity.noContent().build();
    }

    private Optional<Homeserver> localHomeserverOf(String subject) {
        if (subject == null
                || subject.length() > MAX_USER_ID_LENGTH
                || subject.chars().anyMatch(c -> Character.isWhitespace(c) || Character.isISOControl(c))
                || !MatrixIds.isMatrixUserId(subject)) {
            return Optional.empty();
        }
        return homeserverRegistry.findByDomain(MatrixIds.serverNameOf(subject));
    }
}
