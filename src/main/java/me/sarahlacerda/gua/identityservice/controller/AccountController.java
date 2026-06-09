package me.sarahlacerda.gua.identityservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountDeactivateRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountReauthTokenResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountReauthVerifyRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.IdentityResetCredentialsRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.IdentityResetCredentialsResponse;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.security.AccountReauthService;

/**
 * Account management endpoints that require fresh OTP reauthentication. Modeled
 * on the Matrix
 * User-Interactive Authentication {@code m.login.msisdn} stage so the long-term
 * migration to a
 * full MAS deployment can map directly: every privileged operation here demands
 * a phone-OTP proof
 * of possession in addition to the existing session bearer token.
 */
@RestController
@RequestMapping("/account")
@Validated
@RequiredArgsConstructor
@Tag(name = "Account", description = "Privileged account operations gated by phone-OTP reauthentication")
public class AccountController {

    private static final Logger log = LoggerFactory.getLogger(AccountController.class);
    private static final long REAUTH_TOKEN_TTL_SECONDS = 300L;

    private final AccountReauthService reauthService;
    private final AuthenticatedUserAccessor authenticatedUserAccessor;
    private final MatrixAdminClient matrixAdminClient;

    @PostMapping("/reauth/start")
    @Operation(summary = "Send a fresh OTP for account reauthentication", description = "Sends an OTP via SMS to the phone linked to the authenticated user.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "OTP dispatched"),
            @ApiResponse(responseCode = "401", description = "Caller not authenticated", content = @Content),
            @ApiResponse(responseCode = "429", description = "OTP rate limit hit", content = @Content)
    })
    public ResponseEntity<Void> startReauth(
            @RequestHeader(value = "Accept-Language", required = false) String acceptLanguage,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        reauthService.startReauth(userId, servletRequest.getRemoteAddr(), acceptLanguage);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reauth/verify")
    @Operation(summary = "Exchange OTP code for a single-use reauth token")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Reauth token issued", content = @Content(schema = @Schema(implementation = AccountReauthTokenResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid or expired OTP", content = @Content)
    })
    public ResponseEntity<AccountReauthTokenResponse> verifyReauth(
            @RequestBody @Valid AccountReauthVerifyRequest request) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        String token = reauthService.verifyReauth(userId, request.getCode());
        return ResponseEntity.ok(new AccountReauthTokenResponse(token, REAUTH_TOKEN_TTL_SECONDS));
    }

    @PostMapping("/deactivate")
    @Operation(summary = "Deactivate the calling user's Matrix account", description = "Spends a reauth token (from /account/reauth/verify) and asks the homeserver to deactivate the user.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Account deactivated"),
            @ApiResponse(responseCode = "401", description = "Reauth token missing/invalid/expired", content = @Content)
    })
    public ResponseEntity<Void> deactivateAccount(@RequestBody @Valid AccountDeactivateRequest request) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        reauthService.requireValidReauth(userId, request.getReauthToken());
        matrixAdminClient.deactivateUser(userId, request.isEraseData());
        log.info("Account deactivated for {} (erase={})", userId, request.isEraseData());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-identity-credentials")
    @Operation(summary = "Mint a one-time UIA credential for client.resetIdentity", description = "Rotates the homeserver password and returns the new value so the Matrix SDK can answer the m.login.password UIA stage without prompting the user.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Ephemeral UIA credentials issued", content = @Content(schema = @Schema(implementation = IdentityResetCredentialsResponse.class))),
            @ApiResponse(responseCode = "401", description = "Reauth token missing/invalid/expired", content = @Content)
    })
    public ResponseEntity<IdentityResetCredentialsResponse> resetIdentityCredentials(
            @RequestBody @Valid IdentityResetCredentialsRequest request) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        reauthService.requireValidReauth(userId, request.getReauthToken());
        String password = matrixAdminClient.rotatePassword(userId);
        log.info("Issued identity-reset UIA credentials for {}", userId);
        return ResponseEntity.ok(new IdentityResetCredentialsResponse(userId, password));
    }
}
