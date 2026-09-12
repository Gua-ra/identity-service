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
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinStatusResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PinUpdateRequest;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.AccountLocalpartResolver;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.Phase;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactorPolicy;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.ReauthOperation;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

@RestController
@RequestMapping("/security")
@Validated
@RequiredArgsConstructor
@Tag(name = "Security", description = "PIN management and recovery flows")
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

    @GetMapping("/pin/status")
    @Operation(summary = "Check the authenticated user's two-step verification state", description = "Returns hasPin=true once the user has configured a security PIN (drives the 'set up two-step verification' nudge), and how long the fresh-2FA hold on the account's PIN still has to run before that PIN can change the phone number. Read it when about to offer the PIN, not as 'can I change my number now': it is silent about the separate 24h phone-change cooldown, and it does not describe the passkey path, which carries its own hold on the age of the asserted credential and is refused the same way. It also reports which factors the account has REGISTERED, which one to offer first, and which ones a phone change accepts in precedence order, so a client offers the right factor instead of hardcoding the rule. Registration is server truth; whether a registered passkey is usable on this device is not reported and is never accepted as an input.", security = @SecurityRequirement(name = "oidcAccessToken"))
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
        return ResponseEntity.ok(new PinStatusResponse(
                factors.pin(),
                userSecurityService.changePhonePinHoldRemainingSeconds(userId),
                factors.passkey(),
                factors.preferred().name(),
                authFactorPolicy.stepUpFor(ReauthOperation.PHONE_CHANGE).accepted().stream()
                        .map(AuthFactor::name)
                        .toList()));
    }

    @PostMapping("/pin")
    @Operation(summary = "Set the initial account PIN", description = "Stores the user's first security PIN. Updating an existing PIN must use /security/pin/change/start + /complete (OTP-protected).", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "PIN stored"),
            @ApiResponse(responseCode = "400", description = "Validation failed or PIN already set (use change flow)", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content)
    })
    public ResponseEntity<Void> setInitialPin(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Payload containing the user identifier and the new PIN", required = true, content = @Content(schema = @Schema(implementation = PinUpdateRequest.class))) @RequestBody @Valid PinUpdateRequest request) {
        authenticatedUserAccessor.requireUserIdMatches(request.getUserId());
        if (request.getCurrentPin() != null && !request.getCurrentPin().isBlank()) {
            throw new InvalidPinOperationException("Use /security/pin/change/start to change an existing PIN");
        }
        userSecurityService.setInitialPin(request.getUserId(), request.getNewPin());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/pin/change/start")
    @Operation(summary = "Start an OTP-protected PIN change", description = "Verifies the current PIN, enforces the change cooldown, and sends an OTP to the verified phone. Returns a challenge to redeem at /security/pin/change/complete.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Challenge created and OTP sent"),
            @ApiResponse(responseCode = "400", description = "Validation failed or current PIN incorrect", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "425", description = "Cooldown between PIN changes still active", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many attempts (PIN locked or rate limited)", content = @Content)
    })
    public ResponseEntity<PinChangeStartResponse> startPinChange(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Current PIN and phone to receive the OTP", required = true, content = @Content(schema = @Schema(implementation = PinChangeStartRequest.class))) @RequestBody @Valid PinChangeStartRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        String challengeId = userSecurityService.startPinChange(userId, request.getPhone(), request.getCurrentPin(),
                servletRequest.getRemoteAddr());
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

    @PostMapping("/pin/reset")
    @Operation(summary = "Request a PIN reset", description = "Initiates the PIN recovery flow by sending an OTP to the verified phone number.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Reset initiated"),
            @ApiResponse(responseCode = "400", description = "Validation or cooldown failure", content = @Content),
            @ApiResponse(responseCode = "404", description = "User or phone not found", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many reset requests", content = @Content)
    })
    public ResponseEntity<Void> requestPinReset(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "User identifier and verified phone number to receive the OTP", required = true, content = @Content(schema = @Schema(implementation = PinResetRequest.class))) @RequestBody @Valid PinResetRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        userSecurityService.requestPinReset(request.getUserId(), request.getPhone(), servletRequest.getRemoteAddr());
        // Recovery can finally see the rest of the account's factors. It deliberately does not
        // act on them: refusing recovery to an account that holds a passkey would make an
        // unusable credential into an unusable account, with no login and no way back. What it
        // does instead is leave a line behind, because recovering a knowledge factor on an
        // account that also holds a stronger one is worth being able to find later. Recorded
        // after the request was accepted, so a refusal produces nothing and this cannot be
        // used to probe which accounts hold passkeys.
        authFactorPolicy.recordRecoveryRequest(request.getUserId());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/pin/reset/complete")
    @Operation(summary = "Complete a PIN reset", description = "Verifies the OTP sent during the reset request and applies the new PIN.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "PIN reset successful"),
            @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
            @ApiResponse(responseCode = "401", description = "OTP invalid or expired", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many reset attempts", content = @Content)
    })
    public ResponseEntity<Void> completePinReset(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "OTP and new PIN payload to finalize recovery", required = true, content = @Content(schema = @Schema(implementation = PinResetCompleteRequest.class))) @RequestBody @Valid PinResetCompleteRequest request) {
        userSecurityService.completePinReset(request.getUserId(), request.getPhone(), request.getCode(),
                request.getNewPin());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/passkey/stepup/options")
    @Operation(summary = "Start a user-verifying passkey step-up", description = "Begins a WebAuthn assertion that may be spent as the step-up factor on a privileged operation, currently POST /account/phone/change/start. The ceremony is pinned to the authenticated account and demands user verification, so possession of an unlocked device is not on its own enough to stand in for the account PIN. Separate from the sign-in ceremony under /login: a challenge minted here cannot complete a login, and a login challenge cannot be spent here.", security = @SecurityRequirement(name = "oidcAccessToken"))
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
    @Operation(summary = "Start in-app passkey enrollment", description = "Lets an already-signed-in user add a passkey from settings. Builds a login session pinned to the authenticated user and returns a one-time enroll URL the client opens in an authenticated web view, which reuses the same passkey setup step as onboarding.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Enrollment session created; open the returned enrollUrl in a web view"),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content)
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
        //
        // Note what this endpoint does NOT ask for: no PIN, no step-up, nothing but the bearer
        // token. That is on purpose, because demanding a factor to acquire a factor is how an
        // account with a broken credential becomes an account with no way in. What stops a
        // session holder from enrolling a passkey and immediately re-pointing the phone number
        // with it is on the other side, in PhoneChangeService.enforceStepUp: a credential
        // registered inside the fresh-2FA hold cannot settle that step-up yet.
        if (authFactorPolicy.passkeyRegistered(userId)) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_already_registered",
                    "This account already has a passkey.");
        }

        // Same localpart source as login (ADM-001 S6). An enrollment session never issues
        // an authorization code, but it must not carry a value login would refuse.
        List<DirectoryEntry> entries = directoryService.findByUserId(userId);
        String preferredUsername = accountLocalparts.forExistingAccount(userId, entries);

        LoginSession session = new LoginSession();
        session.setUserId(userId);
        // Mark this as an enrollment (not an OIDC login): there is no authorize request,
        // so passkey-setup completion redirects back to the app scheme instead of issuing
        // an authorization code (which would NPE on the absent client id).
        session.setEnroll(true);
        // Pin the session to the authenticated subject. This forces the LOGIN-ONLY
        // contract in LoginFlowController so the enroll flow can never degrade into an
        // open signup/login even though the user is dropped straight at passkey setup.
        session.setReauthUserId(userId);
        session.setDisplayName(displayNameFor(entries, preferredUsername));
        session.setPreferredUsername(preferredUsername);
        // The app scheme the OIDC client uses; only echoed back if the ceremony reaches
        // completion, and never reachable as an open login (reauthUserId is set above).
        session.setRedirectUri(loginProperties.getEnroll().getRedirectUri());
        session.setPhase(Phase.PASSKEY_SETUP);
        session.setCsrfToken(loginSessionService.newToken());

        String sessionId = loginSessionService.create(session);
        String enrollToken = loginSessionService.createEnrollToken(sessionId,
                loginProperties.getEnroll().getTokenTtl());

        // Absolute URL on the web origin that serves the sign-in SPA (same origin the
        // login cookie is first-party to), so the web view loads it directly.
        String enrollUrl = UriComponentsBuilder.fromUriString(oidcProperties.getIssuer())
                .path("/login/passkey/enroll/{token}")
                .buildAndExpand(enrollToken)
                .toUriString();
        return ResponseEntity.ok(new PasskeyEnrollStartResponse(enrollUrl));
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
