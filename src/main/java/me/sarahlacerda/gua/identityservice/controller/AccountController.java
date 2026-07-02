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
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountDeactivateRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountReauthTokenResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountReauthVerifyRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.IdentityResetCredentialsRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.IdentityResetCredentialsResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PhoneChangeCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PhoneChangeStartRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PhoneChangeStartResponse;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.security.AccountReauthService;
import me.sarahlacerda.gua.identityservice.service.security.PhoneChangeService;
import me.sarahlacerda.gua.identityservice.service.security.ReauthOperation;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;

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
        private final TokenRevocationService tokenRevocationService;
        private final DirectoryService directoryService;
        private final PhoneChangeService phoneChangeService;

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
                String token = reauthService.verifyReauth(userId, request.getCode(), request.getOperation());
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
                reauthService.requireValidReauth(userId, request.getReauthToken(), ReauthOperation.DEACTIVATE);
                matrixAdminClient.deactivateUser(userId, request.isEraseData());
                tokenRevocationService.revokeAllTokens(userId);
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
                reauthService.requireValidReauth(userId, request.getReauthToken(), ReauthOperation.IDENTITY_RESET);

                // Reset rotates the homeserver credential for the SAME existing account; it
                // must never mint a new MXID or a new directory row. Pin the operation to the
                // stable MXID already on file for this user so a credential reset can never be
                // turned into a fresh identity (the other half of the identity-reset loop).
                String existingUserId = directoryService.findByUserId(userId).stream()
                                .findFirst()
                                .map(entry -> entry.getUserId())
                                .orElse(userId);
                if (!existingUserId.equals(userId)) {
                        // Defensive: the authenticated MXID and the directory row disagree. Never
                        // proceed against the wrong/new identity.
                        throw new IllegalStateException(
                                        "Identity-reset target does not match the stored account; refusing to reset");
                }

                String password = matrixAdminClient.rotatePassword(existingUserId);
                tokenRevocationService.revokeAllTokens(existingUserId);
                log.info("Issued identity-reset UIA credentials for {} (existing MXID reused)", existingUserId);
                return ResponseEntity.ok(new IdentityResetCredentialsResponse(existingUserId, password));
        }

        @PostMapping("/phone/change/start")
        @Operation(summary = "Start a phone-number change", description = "Spends a PHONE_CHANGE-scoped reauth token and a mandatory step-up factor (account PIN when set, and/or a passkey assertion), then sends an OTP to the NEW number and returns a challenge to redeem at /account/phone/change/complete. Accounts with neither a PIN nor a passkey receive step_up_required and must set up two-step verification first. The OLD number is alerted out of band.", security = @SecurityRequirement(name = "oidcAccessToken"))
        @ApiResponses({
                        @ApiResponse(responseCode = "200", description = "Challenge created and OTP sent to the new number", content = @Content(schema = @Schema(implementation = PhoneChangeStartResponse.class))),
                        @ApiResponse(responseCode = "400", description = "Validation failed, PIN invalid, invalid/equal phone number", content = @Content),
                        @ApiResponse(responseCode = "401", description = "Authentication or reauth/step-up failed", content = @Content),
                        @ApiResponse(responseCode = "403", description = "step_up_required — account has neither a PIN nor a passkey; two-step verification must be set up first", content = @Content),
                        @ApiResponse(responseCode = "409", description = "New number already linked to another account", content = @Content),
                        @ApiResponse(responseCode = "425", description = "Phone-change cooldown still active", content = @Content),
                        @ApiResponse(responseCode = "429", description = "Too many attempts (rate limited or PIN locked)", content = @Content)
        })
        public ResponseEntity<PhoneChangeStartResponse> startPhoneChange(
                        @RequestBody @Valid PhoneChangeStartRequest request,
                        @RequestHeader(value = "Accept-Language", required = false) String acceptLanguage,
                        @Parameter(hidden = true) HttpServletRequest servletRequest) {
                String userId = authenticatedUserAccessor.requireCurrentUserId();
                PhoneChangeService.PhoneChangeStart start = phoneChangeService.startPhoneNumberChange(
                                userId,
                                request.getReauthToken(),
                                request.getNewPhone(),
                                request.getPin(),
                                request.getPasskeyAuthSessionId(),
                                request.getPasskeyCredential(),
                                servletRequest.getRemoteAddr(),
                                acceptLanguage);
                return ResponseEntity.ok(new PhoneChangeStartResponse(start.challengeId(), start.otpExpiresInSeconds()));
        }

        @PostMapping("/phone/change/complete")
        @Operation(summary = "Complete a phone-number change", description = "Redeems a challenge from /account/phone/change/start with the OTP delivered to the new number. On success the account's phone mapping is atomically switched, outstanding sessions are revoked, and the new number is alerted.", security = @SecurityRequirement(name = "oidcAccessToken"))
        @ApiResponses({
                        @ApiResponse(responseCode = "204", description = "Phone number changed"),
                        @ApiResponse(responseCode = "400", description = "Validation failed or OTP invalid", content = @Content),
                        @ApiResponse(responseCode = "401", description = "Authentication required or challenge missing/expired", content = @Content),
                        @ApiResponse(responseCode = "409", description = "New number already linked to another account", content = @Content)
        })
        public ResponseEntity<Void> completePhoneChange(
                        @RequestBody @Valid PhoneChangeCompleteRequest request,
                        @Parameter(hidden = true) HttpServletRequest servletRequest) {
                String userId = authenticatedUserAccessor.requireCurrentUserId();
                phoneChangeService.completePhoneNumberChange(userId, request.getChallengeId(), request.getCode(),
                                servletRequest.getRemoteAddr());
                return ResponseEntity.noContent().build();
        }
}
