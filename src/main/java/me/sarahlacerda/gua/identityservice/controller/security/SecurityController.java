package me.sarahlacerda.gua.identityservice.controller.security;

import java.util.List;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.PasskeyEnrollStartResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PasskeyStepUpStartResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeStartRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeStartResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PinEnrollStartResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PinStatusResponse;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.EndpointRetiredException;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.exception.StepUpRequiredException;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.AccountLocalpartResolver;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.Phase;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryService;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactorPolicy;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.PinChangeService;
import me.sarahlacerda.gua.identityservice.service.security.ReauthOperation;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

@RestController
@RequestMapping("/security")
@Validated
@RequiredArgsConstructor
@Tag(name = "Security", description = "PIN management, factor enrollment and account recovery cancel")
public class SecurityController {

    private final UserSecurityService userSecurityService;
    private final AuthenticatedUserAccessor authenticatedUserAccessor;
    private final IdentityServiceProperties properties;
    private final DirectoryService directoryService;
    private final LoginSessionService loginSessionService;
    private final LoginFlowProperties loginProperties;
    private final OidcProperties oidcProperties;
    private final PasskeyService passkeyService;
    private final AuthFactorPolicy authFactorPolicy;
    private final AccountLocalpartResolver accountLocalparts;
    private final PinChangeService pinChangeService;
    private final AccountRecoveryService accountRecoveryService;

    @GetMapping("/pin/status")
    @Operation(summary = "Check the authenticated user's two-step verification state", description = "Returns hasPin=true once the user has configured a security PIN (drives the 'set up two-step verification' nudge), and how long the fresh-2FA hold on the account's PIN still has to run before that PIN can change the phone number. Read it when about to offer the PIN, not as 'can I change my number now': it is silent about the separate 24h phone-change cooldown, and it does not describe the passkey path, which carries its own hold on the age of the asserted credential and is refused the same way. It also reports which factors the account has REGISTERED, which one to offer first, and which ones a phone change accepts in precedence order, so a client offers the right factor instead of hardcoding the rule. Registration is server truth; whether a registered passkey is usable on this device is not reported and is never accepted as an input. Finally it reports whether a delayed account recovery is live on the account (accountRecoveryPending), with when it can be finished and when it expires, so every signed-in app can show a banner and offer POST /security/recovery/cancel.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "PIN status"),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content)
    })
    public ResponseEntity<PinStatusResponse> pinStatus() {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        // The factor report is one-way on purpose. The server tells the client which factors
        // the account has registered and which ones a phone change accepts, so the client can
        // offer the right thing first instead of guessing. The client never tells the server
        // that a factor is unavailable: that claim costs an attacker nothing, so it could
        // only ever be a way to ask for something weaker.
        AuthFactorPolicy.RegisteredFactors factors = authFactorPolicy.registeredFactors(userId);
        AccountRecoveryState recovery = accountRecoveryService.pendingFor(userId).orElse(null);
        return ResponseEntity.ok(new PinStatusResponse(
                factors.pin(),
                userSecurityService.changePhonePinHoldRemainingSeconds(userId),
                factors.passkey(),
                factors.preferred().name(),
                authFactorPolicy.stepUpFor(ReauthOperation.PHONE_CHANGE).accepted().stream()
                        .map(AuthFactor::name)
                        .toList(),
                recovery != null,
                recovery == null ? null : recovery.completableAtEpochSeconds(),
                recovery == null ? null : recovery.expiresAtEpochSeconds()));
    }

    @PostMapping("/pin")
    @Operation(summary = "Set the initial account PIN (step-up required)", description = "Always 403 step_up_required. A bearer session on its own must not add a durable factor: a session is the thing an attacker gets, and a PIN set from one is a second way into the account for whoever holds it. Setting a first PIN now runs through POST /security/pin/enroll/start, whose web session confirms the account first, with a passkey, the existing PIN, or the account's own number and a code sent to it. Changing an existing PIN still uses /security/pin/change/start + /complete.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "403", description = "step_up_required: use POST /security/pin/enroll/start", content = @Content)
    })
    public ResponseEntity<Void> setInitialPin() {
        // Takes no body and touches nothing, so an older client is told what to do instead of
        // tripping a validation error on a payload that was never going to be stored.
        throw new StepUpRequiredException(
                "Confirm it is you before adding a PIN: start at POST /security/pin/enroll/start.");
    }

    @PostMapping("/pin/enroll/start")
    @Operation(summary = "Start in-app PIN enrollment", description = "Lets an already-signed-in user add a PIN from settings. Mirrors POST /security/passkey/enroll/start: it builds a login session pinned to the authenticated user and returns a one-time enroll URL the client opens in an authenticated web view. The session starts at ENROLL_STEP_UP and stores nothing until the account is confirmed there.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Enrollment session created; open the returned enrollUrl in a web view"),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "409", description = "pin_already_set: the account already has a PIN, or step_up_unavailable: the only factor this account holds is one this deployment cannot run", content = @Content)
    })
    public ResponseEntity<PinEnrollStartResponse> startPinEnrollment() {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        // Same shape as the passkey guard below: an account that already has one is told so,
        // rather than being walked into a setup step that would refuse under the row lock.
        if (authFactorPolicy.pinRegistered(userId)) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "pin_already_set",
                    "This account already has a PIN.");
        }
        return ResponseEntity.ok(new PinEnrollStartResponse(
                startFactorEnrollment(userId, LoginSession.EnrollTarget.PIN)));
    }

    @PostMapping("/pin/change/start")
    @Operation(summary = "Start an OTP-protected PIN change", description = "Enforces the change cooldown, authorizes the change with a user-verifying passkey step-up assertion (preferred) or the current PIN, and sends an OTP to the verified phone. Returns a challenge to redeem at /security/pin/change/complete.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Challenge created and OTP sent"),
            @ApiResponse(responseCode = "400", description = "Validation failed, current PIN incorrect, passkey assertion refused, or twofa_cooldown_active for a freshly registered passkey", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "425", description = "Cooldown between PIN changes still active", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many attempts (PIN locked or rate limited)", content = @Content)
    })
    public ResponseEntity<PinChangeStartResponse> startPinChange(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Phone to receive the OTP, and a passkey step-up assertion or the current PIN", required = true, content = @Content(schema = @Schema(implementation = PinChangeStartRequest.class))) @RequestBody @Valid PinChangeStartRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        String challengeId = pinChangeService.start(userId, request.getPhone(), request.getCurrentPin(),
                request.getPasskeyStepUpId(), request.getPasskeyCredential(), servletRequest.getRemoteAddr());
        long ttlSeconds = properties.getSecurity().getPinChangeChallengeTtl().toSeconds();
        return ResponseEntity.ok(new PinChangeStartResponse(challengeId, ttlSeconds));
    }

    @PostMapping("/pin/change/complete")
    @Operation(summary = "Complete an OTP-protected PIN change", description = "Redeems a challenge from /security/pin/change/start together with the OTP delivered by SMS and the new PIN.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "PIN changed"),
            @ApiResponse(responseCode = "400", description = "Validation failed or OTP invalid", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required or challenge missing/expired", content = @Content),
            @ApiResponse(responseCode = "425", description = "Cooldown between PIN changes still active", content = @Content)
    })
    public ResponseEntity<Void> completePinChange(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Challenge identifier, OTP, and new PIN", required = true, content = @Content(schema = @Schema(implementation = PinChangeCompleteRequest.class))) @RequestBody @Valid PinChangeCompleteRequest request) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        userSecurityService.completePinChange(userId, request.getChallengeId(), request.getOtpCode(),
                request.getNewPin());
        return ResponseEntity.noContent().build();
    }

    @PostMapping({ "/pin/reset", "/pin/reset/complete" })
    @Operation(summary = "Retired: unauthenticated PIN reset", description = "Always 410 endpoint_retired. The unauthenticated reset shared the recovery episode but not its rules (it could reset a PIN on an account whose passkey was still in use). Recovery now runs inside the interactive login, from the PIN or passkey step after an OTP: POST /login/recovery/start and /login/recovery/complete.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "410", description = "This endpoint is retired", content = @Content)
    })
    public ResponseEntity<Void> retiredPinReset() {
        // Takes no body and touches nothing, so an old client learns the path is gone instead of
        // tripping a validation error first.
        throw new EndpointRetiredException(
                "PIN reset moved into sign-in. Open Gua, enter your number, and choose the recovery option.");
    }

    @PostMapping("/recovery/cancel")
    @Operation(summary = "Cancel a delayed account recovery", description = "The account holder's cancel, from any signed-in app showing the recovery banner. Ends a live recovery episode on the authenticated account and counts as account activity, so a new recovery cannot be requested until the dormancy period has passed again. 204 whether or not a recovery was live.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "No recovery is live on the account any more"),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content)
    })
    public ResponseEntity<Void> cancelAccountRecovery(@Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        accountRecoveryService.cancel(userId, servletRequest.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/passkey/stepup/options")
    @Operation(summary = "Start a user-verifying passkey step-up", description = "Begins a WebAuthn assertion that may be spent as the step-up factor on a privileged operation, currently POST /account/phone/change/start and POST /security/pin/change/start. The ceremony is pinned to the authenticated account and demands user verification, so possession of an unlocked device is not on its own enough to stand in for the account PIN. Separate from the sign-in ceremony under /login: a challenge minted here cannot complete a login, and a login challenge cannot be spent here.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Assertion options created"),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "404", description = "Passkeys are disabled on this deployment", content = @Content),
            @ApiResponse(responseCode = "409", description = "The account has no registered passkey to verify with", content = @Content)
    })
    public ResponseEntity<PasskeyStepUpStartResponse> startPasskeyStepUp() {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        String stepUpId = UUID.randomUUID().toString();
        return ResponseEntity.ok(new PasskeyStepUpStartResponse(
                stepUpId, passkeyService.startStepUpAssertion(stepUpId, userId)));
    }

    @PostMapping("/passkey/enroll/start")
    @Operation(summary = "Start in-app passkey enrollment", description = "Lets an already-signed-in user add a passkey from settings. Builds a login session pinned to the authenticated user and returns a one-time enroll URL the client opens in an authenticated web view. The session starts at ENROLL_STEP_UP and runs the passkey setup step only once the account has been confirmed there.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Enrollment session created; open the returned enrollUrl in a web view"),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "409", description = "passkey_already_registered: the account already has a passkey, or step_up_unavailable: the only factor this account holds is one this deployment cannot run", content = @Content)
    })
    public ResponseEntity<PasskeyEnrollStartResponse> startPasskeyEnrollment() {
        String userId = authenticatedUserAccessor.requireCurrentUserId();

        // Enrolling a second passkey for an account that already has one cannot succeed.
        // The ceremony excludes the credentials the account already holds, so the
        // authenticator refuses, and the browser reports that refusal as a failure rather
        // than as "you already have one". Every login route already declines to offer
        // setup in this case, in LoginFlowController.advanceToPasskeySetup. This entry
        // point skipped the same check, so opening it from settings walked straight into a
        // ceremony that was guaranteed to fail and left nothing behind, which read from
        // the outside like passkeys being broken.
        // Same question, same answer as LoginFlowController.advanceToPasskeySetup, because both
        // now ask AuthFactorPolicy rather than each assembling it from isEnabled + hasPasskey.
        if (authFactorPolicy.passkeyRegistered(userId)) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_already_registered",
                    "This account already has a passkey.");
        }

        return ResponseEntity.ok(new PasskeyEnrollStartResponse(
                startFactorEnrollment(userId, LoginSession.EnrollTarget.PASSKEY)));
    }

    /**
     * Builds the enrollment session both entry points hand out, and returns the one-time URL
     * that opens it.
     *
     * <p>
     * What the two enrollment endpoints ask for is the bearer token, and what the session they
     * create can do with that alone is nothing: it starts at {@code ENROLL_STEP_UP}, where the account has to
     * be confirmed with a user-verifying passkey assertion, the account PIN, or, for an account
     * that holds neither, its own number and a code sent to that number. Only then does the
     * session reach the step that stores a factor. A session is the thing an attacker gets hold
     * of, so a session on its own must not be able to leave a new way in behind it.
     *
     * <p>
     * The step-up runs in a web view rather than in the app because that is the only place a
     * passkey assertion can be performed on every platform this ships to, and asking for the
     * strongest proof the account can give was the point.
     */
    private String startFactorEnrollment(String userId, LoginSession.EnrollTarget target) {
        requireAProofThisDeploymentCanRun(userId);

        // Same localpart source as login (ADM-001 S6). An enrollment session never issues
        // an authorization code, but it must not carry a value login would refuse.
        List<DirectoryEntry> entries = directoryService.findByUserId(userId);
        String preferredUsername = accountLocalparts.forExistingAccount(userId, entries);

        LoginSession session = new LoginSession();
        session.setUserId(userId);
        // Mark this as an enrollment (not an OIDC login): there is no authorize request,
        // so completion redirects back to the app scheme instead of issuing an authorization
        // code (which would NPE on the absent client id).
        session.setEnroll(true);
        session.setEnrollTarget(target);
        // Pin the session to the authenticated subject. This forces the LOGIN-ONLY
        // contract in LoginFlowController so the enroll flow can never degrade into an
        // open signup/login even though the user is dropped straight into enrollment.
        session.setReauthUserId(userId);
        session.setDisplayName(displayNameFor(entries, preferredUsername));
        session.setPreferredUsername(preferredUsername);
        // The app scheme the OIDC client uses; only echoed back if enrollment reaches
        // completion, and never reachable as an open login (reauthUserId is set above).
        session.setRedirectUri(loginProperties.getEnroll().getRedirectUri());
        session.setPhase(Phase.ENROLL_STEP_UP);
        session.setCsrfToken(loginSessionService.newToken());

        String sessionId = loginSessionService.create(session);
        String enrollToken = loginSessionService.createEnrollToken(sessionId,
                loginProperties.getEnroll().getTokenTtl());

        // Absolute URL on the web origin that serves the sign-in SPA (same origin the
        // login cookie is first-party to), so the web view loads it directly.
        return UriComponentsBuilder.fromUriString(oidcProperties.getIssuer())
                .path("/login/enroll/{token}")
                .buildAndExpand(enrollToken)
                .toUriString();
    }

    /**
     * Refuses to open an enrollment session whose step-up no proof could pass.
     *
     * <p>
     * The step-up takes a passkey assertion, the account PIN, or, only from an account that
     * holds neither, its own number and a code sent to it. One account falls outside all three:
     * one that holds a passkey and no PIN on a deployment where passkeys are switched off. The
     * assertion cannot run here, there is no PIN to give, and the SMS proof is not a way out,
     * because it is confined to accounts that hold nothing at all (see
     * {@link AuthFactorPolicy} on held versus registered, and why switching passkeys off must
     * not downgrade such an account).
     *
     * <p>
     * Left to run, that session would publish {@code passkeyRegistered=false} and
     * {@code preferredFactor=PHONE_OTP}, which points the web at the phone step, and then be
     * refused there with {@code step_up_factor_available}: its own published state pointing the
     * client at the one path the server will not take. Saying so at the entry point is the
     * honest answer. The way back for that account is the delayed recovery, which waits.
     */
    private void requireAProofThisDeploymentCanRun(String userId) {
        boolean canProve = authFactorPolicy.passkeyRegistered(userId)
                || authFactorPolicy.pinRegistered(userId)
                || authFactorPolicy.loginPolicy(userId).factorSetupRequired();
        if (!canProve) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "step_up_unavailable",
                    "This account is confirmed with a passkey, and passkeys are turned off here.");
        }
    }

    /**
     * Resolves a human-friendly display name for the passkey credential from the
     * user's directory rows, falling back to the account's localpart when the
     * directory has no display name for the user.
     */
    private static String displayNameFor(List<DirectoryEntry> entries, String localpart) {
        return entries.stream()
                .map(DirectoryEntry::getDisplayName)
                .filter(name -> name != null && !name.isBlank())
                .findFirst()
                .orElse(localpart);
    }
}
