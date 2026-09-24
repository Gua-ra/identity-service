package me.sarahlacerda.gua.identityservice.controller.security;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.util.UriComponentsBuilder;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityStepUpStartRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityStepUpStartResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.FactorEnrollStartRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PasskeyEnrollStartResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PasskeyRemoveRequest;
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
import me.sarahlacerda.gua.identityservice.service.security.PasskeyRemovalService;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.PinChangeService;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityWebStepUpService;
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
    private final PasskeyRemovalService passkeyRemovalService;
    private final AuthorityWebStepUpService authorityWebStepUps;

    @GetMapping("/pin/status")
    @Operation(summary = "Check the authenticated user's two-step verification state", description = "Returns hasPin=true once the user has configured a security PIN (drives the 'set up two-step verification' nudge), and how long the fresh-2FA hold on the account's PIN still has to run before that PIN can change the phone number. Read it when about to offer the PIN, not as 'can I change my number now': it is silent about the separate 24h phone-change cooldown, and it does not describe the passkey path, which carries its own hold on the age of the asserted credential and is refused the same way. It also reports which factors the account has REGISTERED, which one to offer first, and which ones a phone change accepts in precedence order, so a client offers the right factor instead of hardcoding the rule. Registration is server truth; whether a registered passkey is usable on this device is not reported and is never accepted as an input. Finally it reports whether a delayed account recovery is live on the account (accountRecoveryPending), with when it can be finished and when it expires, so every signed-in app can show a banner and offer POST /security/recovery/cancel, and the two configured waits (accountRecoveryDormancySeconds, accountRecoveryWaitSeconds), which are reported whether or not a recovery is live because they are configuration rather than episode state: a client that states them itself is right only on a deployment left at the defaults.", security = @SecurityRequirement(name = "oidcAccessToken"))
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
                recovery == null ? null : recovery.expiresAtEpochSeconds(),
                // The two waits are configuration, not episode state, so they are reported whether
                // or not one is live. A client that states them itself is right only on a
                // deployment left at the defaults, which the dev target is not.
                properties.getSecurity().getAccountRecoveryDormancy().toSeconds(),
                properties.getSecurity().getAccountRecoveryWait().toSeconds()));
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
    @Operation(summary = "Start in-app PIN enrollment", description = "Lets an already-signed-in user add a PIN from settings. Mirrors POST /security/passkey/enroll/start: it builds a login session pinned to the authenticated user and returns a one-time enroll URL the client opens in an authenticated web view. The session starts at ENROLL_STEP_UP and stores nothing until the account is confirmed there. The body is optional and carries at most the app-scheme redirect this build answers, which must be one the deployment allows.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Enrollment session created; open the returned enrollUrl in a web view"),
            @ApiResponse(responseCode = "400", description = "invalid_redirect_uri: the named redirect is not one this deployment allows. Retry once with no redirectUri to take the deployment's default.", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "409", description = "pin_already_set: the account already has a PIN, or step_up_unavailable: the only factor this account holds is one this deployment cannot run", content = @Content)
    })
    public ResponseEntity<PinEnrollStartResponse> startPinEnrollment(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Optional. The app-scheme redirect this build answers.", required = false, content = @Content(schema = @Schema(implementation = FactorEnrollStartRequest.class))) @RequestBody(required = false) FactorEnrollStartRequest request) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        // Same shape as the passkey guard below: an account that already has one is told so,
        // rather than being walked into a setup step that would refuse under the row lock.
        if (authFactorPolicy.pinRegistered(userId)) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "pin_already_set",
                    "This account already has a PIN.");
        }
        return ResponseEntity.ok(new PinEnrollStartResponse(
                startFactorEnrollment(userId, LoginSession.EnrollTarget.PIN, requestedRedirectUri(request))));
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

    @PostMapping("/passkey/credentials/{credentialId}/remove")
    @Operation(summary = "Remove one passkey credential", description = "Removes the named credential after a step-up: a user-verifying passkey assertion, or the account PIN. Until this existed the only way to remove a credential was to remove them all, so an owner locking a thief out of a stolen device had to wipe every credential and register a new one, which put their own remaining factor inside the fresh-2FA hold. The account's last factor is refused (409 factor_required): the way to be rid of every credential is still the delayed recovery, which assumes they are lost. A credential id that is not this account's is answered the same way as one that does not exist, so this cannot be used to ask whose a credential is.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Removed, or there was nothing with that id"),
            @ApiResponse(responseCode = "400", description = "invalid_pin or invalid_request", content = @Content),
            @ApiResponse(responseCode = "401", description = "Caller not authenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "step_up_required, or the assertion resolves to another account", content = @Content),
            @ApiResponse(responseCode = "409", description = "factor_required: that is the account's last factor", content = @Content),
            @ApiResponse(responseCode = "429", description = "pin_locked", content = @Content)
    })
    public ResponseEntity<Void> removePasskeyCredential(@PathVariable String credentialId,
            @RequestBody(required = false) @Valid PasskeyRemoveRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        PasskeyRemoveRequest body = request == null ? new PasskeyRemoveRequest() : request;
        passkeyRemovalService.remove(userId, credentialId, body.getPasskeyStepUpId(), body.getPasskeyCredential(),
                body.getPin(), servletRequest.getRemoteAddr());
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
    @Operation(summary = "Start in-app passkey enrollment", description = "Lets an already-signed-in user add a passkey from settings. Builds a login session pinned to the authenticated user and returns a one-time enroll URL the client opens in an authenticated web view. The session starts at ENROLL_STEP_UP and runs the passkey setup step only once the account has been confirmed there. The body is optional and carries at most the app-scheme redirect this build answers, which must be one the deployment allows.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Enrollment session created; open the returned enrollUrl in a web view"),
            @ApiResponse(responseCode = "400", description = "invalid_redirect_uri: the named redirect is not one this deployment allows. Retry once with no redirectUri to take the deployment's default.", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "409", description = "passkey_already_registered: the account already has a passkey, or step_up_unavailable: the only factor this account holds is one this deployment cannot run", content = @Content)
    })
    public ResponseEntity<PasskeyEnrollStartResponse> startPasskeyEnrollment(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Optional. The app-scheme redirect this build answers.", required = false, content = @Content(schema = @Schema(implementation = FactorEnrollStartRequest.class))) @RequestBody(required = false) FactorEnrollStartRequest request) {
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
                startFactorEnrollment(userId, LoginSession.EnrollTarget.PASSKEY, requestedRedirectUri(request))));
    }

    @PostMapping("/authority/step-up/start")
    @Operation(summary = "Start the web step-up one authority transition is scoped to",
            description = "The same handoff POST /security/passkey/enroll/start uses, carrying an authority "
                    + "purpose instead of a factor to add: it builds a login session pinned to the "
                    + "authenticated user, stamped with that purpose and with the hash of this access token, "
                    + "and returns a one-time URL the client opens in a web sheet. The page runs a "
                    + "user-verifying passkey assertion, or asks for the account PIN, and on success the "
                    + "session records a step-up this account may spend once at POST /account/authority/"
                    + "challenge for that purpose. It exists because the assertion cannot be produced natively "
                    + "on every platform, and a passkey-only account must never be told to add a PIN to gain "
                    + "authority. No code is sent to the account's number at any step of it. The body carries "
                    + "the purpose and at most the app-scheme redirect this build answers.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Step-up session created; open the returned "
                    + "stepUpUrl in a web sheet"),
            @ApiResponse(responseCode = "400", description = "invalid_redirect_uri: the named redirect is not "
                    + "one this deployment allows. Retry once with no redirectUri to take the deployment's "
                    + "default.", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_native_session_required: the browser "
                    + "holds no authority and may not open one of these", content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_step_up_purpose_refused for a purpose "
                    + "that asks for no factor, or authority_step_up_unavailable when the account holds "
                    + "neither a passkey this deployment can assert nor a PIN", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AuthorityStepUpStartResponse> startAuthorityStepUp(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "The transition being "
                    + "confirmed, and optionally the app-scheme redirect this build answers", required = true,
                    content = @Content(schema = @Schema(implementation = AuthorityStepUpStartRequest.class)))
            @RequestBody @Valid AuthorityStepUpStartRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        // The flag, the native-session rule and the purpose, all before any account state is read: whether
        // this caller may open a sheet at all is a fact about the request.
        authorityWebStepUps.requireMayOpen(authenticatedUserAccessor.currentClientId(), request.getPurpose());
        requireAFactorTheSheetCanRun(userId);

        LoginSession session = handoffSession(userId, request.getRedirectUri());
        session.setPhase(Phase.AUTHORITY_STEP_UP);
        session.setAuthorityPurpose(request.getPurpose().name());
        // Bound to the token that asked, so the proof is not spendable by another session of this account.
        session.setAuthoritySessionHash(
                AuthorityWebStepUpService.sessionHash(servletRequest.getHeader("Authorization")));
        return ResponseEntity.ok(new AuthorityStepUpStartResponse(openHandoff(session)));
    }

    /**
     * Refuses to open an authority step-up whose page would have nothing to ask for.
     *
     * <p>Two proofs reach that page and there is no third: a passkey assertion, and the account PIN. An
     * account that holds neither cannot confirm an authority transition at all, which is ADM-009 decision 4's
     * own answer rather than a gap here: adoption needs a step-up, so nobody can root that account either,
     * and decision 9 forbids the code that would otherwise stand in. Saying so at the entry point is the
     * honest answer, where opening the sheet would put a person in front of a page whose every button is
     * already refused.
     *
     * <p>Deliberately not the enrollment precheck. That one counts an account holding no factor as provable,
     * because enrollment may confirm it with its own number and a code sent to it. No authority step reads a
     * code, so that branch does not exist here.
     */
    private void requireAFactorTheSheetCanRun(String userId) {
        if (!authFactorPolicy.passkeyRegistered(userId) && !authFactorPolicy.pinRegistered(userId)) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "authority_step_up_unavailable",
                    "Add a passkey or a PIN to this account first.");
        }
    }

    /**
     * The one thing an enrollment body may carry, and the only value either endpoint reads off
     * the request. The body itself is optional, so a client that sends none, which is every
     * client built before this existed, is indistinguishable from one that names nothing.
     */
    private static String requestedRedirectUri(FactorEnrollStartRequest request) {
        return request == null ? null : request.getRedirectUri();
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
    private String startFactorEnrollment(String userId, LoginSession.EnrollTarget target,
            String requestedRedirectUri) {
        requireAProofThisDeploymentCanRun(userId);

        LoginSession session = handoffSession(userId, requestedRedirectUri);
        // Mark this as an enrollment (not an OIDC login): there is no authorize request,
        // so completion redirects back to the app scheme instead of issuing an authorization
        // code (which would NPE on the absent client id).
        session.setEnroll(true);
        session.setEnrollTarget(target);
        session.setPhase(Phase.ENROLL_STEP_UP);
        return openHandoff(session);
    }

    /**
     * The session both handoffs share: pinned to the authenticated subject, carrying no OIDC request, and
     * addressed at one app scheme this deployment allows.
     *
     * <p>Extracted rather than copied because the two callers differ in three lines and agree on everything
     * that matters: which subject, which redirects are allowed, and that neither may ever issue an
     * authorization code. A second copy of this is a second place for the allowlist to be forgotten.
     *
     * <p>The caller sets the phase, because the phase is the whole of what the two are for.
     */
    private LoginSession handoffSession(String userId, String requestedRedirectUri) {
        // Resolved first, before any account state is read: whether a redirect is one this
        // deployment allows is a fact about the request alone, so a refused one stops here
        // rather than being carried on an object that is about to be filled in.
        String redirectUri = enrollRedirectUri(requestedRedirectUri);

        // Same localpart source as login (ADM-001 S6). Neither of these sessions issues
        // an authorization code, but neither may carry a value login would refuse.
        List<DirectoryEntry> entries = directoryService.findByUserId(userId);
        String preferredUsername = accountLocalparts.forExistingAccount(userId, entries);

        LoginSession session = new LoginSession();
        session.setUserId(userId);
        // Pin the session to the authenticated subject. This forces the LOGIN-ONLY
        // contract in LoginFlowController so neither handoff can degrade into an
        // open signup/login even though the user is dropped straight into a step.
        session.setReauthUserId(userId);
        session.setDisplayName(displayNameFor(entries, preferredUsername));
        session.setPreferredUsername(preferredUsername);
        // An app scheme this deployment allows; only echoed back if the sheet reaches
        // completion, and never reachable as an open login (reauthUserId is set above).
        session.setRedirectUri(redirectUri);
        session.setCsrfToken(loginSessionService.newToken());
        return session;
    }

    /** Stores the session and returns the one-time URL that opens it in a web view. */
    private String openHandoff(LoginSession session) {
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
     * Where the enrollment sheet sends the app back when the ceremony completes.
     *
     * <p>
     * The app that opened the sheet is the app that has to receive the handoff, and each build
     * registers its own scheme: the store build answers {@code global.gua}, a QA build
     * {@code global.gua.dev}, an Android debug build {@code global.gua.debug}. One configured
     * value for the whole deployment meant the sheet on a QA build handed off to a scheme that
     * build does not answer, so it never dismissed itself, and on a phone that also has the
     * store build installed the completion went to the wrong app.
     *
     * <p>
     * Three steps, in this order:
     *
     * <ol>
     * <li>the redirect the caller named, when the deployment's allowlist has it. The build is
     * the only party that knows which build it is, because an app's bearer is a homeserver token
     * validated through whoami and so names no OIDC client of ours to read the scheme off;</li>
     * <li>the app scheme registered by the OIDC client the token was issued to, for a token this
     * service minted itself;</li>
     * <li>the configured default.</li>
     * </ol>
     *
     * <p>
     * Letting the caller name it is the part that needs the bound. This is a bearer endpoint
     * that hands back a URL on our own origin, and one that honoured any redirect a caller sent
     * would hand a session's completion wherever the caller asked. So a named value reaches a
     * session through {@link #allowlisted(String)} and no other way: the operator says which
     * schemes exist, the caller only says which of them is asking.
     *
     * <p>
     * Only an app scheme is taken from a client registration. What is being chosen is the thing
     * the web view opening this sheet is listening for, and a client whose redirects are all web
     * origins, the authentication service among them, is not an app that can be handed back to.
     */
    private String enrollRedirectUri(String requestedRedirectUri) {
        if (StringUtils.hasText(requestedRedirectUri)) {
            return allowlisted(requestedRedirectUri);
        }
        return clientRegisteredAppScheme().orElseGet(() -> loginProperties.getEnroll().getRedirectUri());
    }

    /**
     * Matches a caller-named redirect against the deployment's allowlist and hands back the
     * configured entry, not the string that arrived, so what is stamped on a session is always a
     * value an operator wrote down.
     *
     * <p>
     * The match is exact. An allowlist that normalized, prefix-matched or ignored case would be
     * deciding on the caller's behalf what counts as the same app, which is the one judgement
     * this list exists to take away from the caller.
     *
     * <p>
     * A value that is not on the list is refused, and the refusal carries no part of it: not in
     * the message, not in a log line. It arrived from the caller, so echoing it back would make
     * this a reflector, and an operator learns which scheme to add from the builds being shipped
     * rather than from a request the server already refused. Clients treat the refusal as a
     * signal to retry once with no redirect, which lands on the default, so a deployment that
     * has not been told about a build yet costs QA a redirect, never the enrollment.
     */
    private String allowlisted(String requestedRedirectUri) {
        String requested = requestedRedirectUri.trim();
        return loginProperties.getEnroll().allowedRedirectUris().stream()
                .filter(requested::equals)
                .findFirst()
                .orElseThrow(() -> new LoginFlowException(HttpStatus.BAD_REQUEST, "invalid_redirect_uri",
                        "That is not a redirect this deployment allows for enrollment."));
    }

    /**
     * The app scheme registered by the OIDC client the bearer token was issued to, read off the
     * audience this service verified before accepting the token.
     *
     * <p>
     * Empty when the token names no client of ours, which is every homeserver-issued token, and
     * when the client it names registered no app scheme.
     */
    private Optional<String> clientRegisteredAppScheme() {
        return authenticatedUserAccessor.currentClientId()
                .flatMap(clientId -> oidcProperties.getClients().stream()
                        .filter(client -> clientId.equals(client.getClientId()))
                        .findFirst())
                .flatMap(client -> client.getRedirectUris().stream()
                        .filter(SecurityController::isAppScheme)
                        .findFirst());
    }

    /** A redirect an app answers, rather than a browser: anything that is not an http(s) URL. */
    private static boolean isAppScheme(String redirectUri) {
        String lower = redirectUri.toLowerCase(java.util.Locale.ROOT);
        return !lower.startsWith("http://") && !lower.startsWith("https://");
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
