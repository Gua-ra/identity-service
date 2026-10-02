package me.sarahlacerda.gua.identityservice.controller.oidc;

import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.domain.Homeserver;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.StepUpRequiredException;
import me.sarahlacerda.gua.identityservice.exception.UsernameTakenException;
import me.sarahlacerda.gua.identityservice.service.AccountLocalpartResolver;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.MatrixProvisioningService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberNormalizer;
import me.sarahlacerda.gua.identityservice.service.RegistrationGuard;
import me.sarahlacerda.gua.identityservice.service.account.AccountCreationService;
import me.sarahlacerda.gua.identityservice.service.account.AccountGenesisService;
import me.sarahlacerda.gua.identityservice.service.routing.AccountPlacementContext;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRouter;
import me.sarahlacerda.gua.identityservice.service.UsernamePolicy;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.Phase;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.SessionFactor;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.security.AccountReauthService;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryService;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactorPolicy;
import me.sarahlacerda.gua.identityservice.service.security.LoginFactorEnrollmentService;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.EndOtherSessionsService;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

/**
 * Server side of the interactive OIDC login flow. {@code GET /oauth2/authorize} parks the OIDC request
 * in a Redis-backed {@link LoginSession} and drops an opaque cookie; the {@code gua-idp-web} app then
 * drives these endpoints through phone, OTP, then PIN or passkey (returning user) or profile (new
 * user). On success an authorization code is issued and the UI gets the redirect URL back to the
 * requesting client (MAS).
 *
 * <p>A code is issued only to a session that authenticated with a factor (see {@link SessionFactor}).
 * The phone OTP proves the number and never finishes a sign-in on its own.
 *
 * <p>The same endpoints serve in-app factor enrollment, which is not a sign-in: the session starts at
 * {@code ENROLL_STEP_UP} and issues no authorization code.
 *
 * <p>State-changing calls are protected by a double-submit CSRF token issued in
 * {@code GET /login/context} and a {@code SameSite=Lax} session cookie.
 */
@RestController
@RequestMapping("/login")
@Validated
@RequiredArgsConstructor
@Tag(name = "Interactive Login", description = "Browser-driven OIDC login flow (phone, OTP, PIN/profile) used by gua-idp-web")
public class LoginFlowController {

    private static final Logger log = LoggerFactory.getLogger(LoginFlowController.class);

    private static final String CSRF_HEADER = "X-CSRF-Token";
    private static final String COOKIE_NAME_EXPR = "${idp.login.cookie-name:gua_login}";

    /**
     * The only steps whose state may carry the account's registered factors. An allow list, so a phase
     * added later publishes nothing by default. Before these steps the session holds only a typed phone
     * number, so reporting factors there would let any caller probe any number.
     */
    private static final Set<Phase> FACTOR_REPORT_PHASES = EnumSet.of(Phase.PIN_REQUIRED, Phase.PASSKEY_REQUIRED,
            Phase.PIN_SETUP, Phase.PASSKEY_SETUP, Phase.ENROLL_STEP_UP);

    /**
     * The steps from which the delayed account recovery may be offered. See
     * {@link #recoveryAvailable(LoginSession)}.
     */
    private static final Set<Phase> RECOVERY_PHASES = EnumSet.of(Phase.PIN_REQUIRED, Phase.PASSKEY_REQUIRED);

    private final LoginSessionService loginSessionService;
    private final LoginFlowProperties properties;
    private final OtpService otpService;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final PhoneNumberMasker phoneNumberMasker;
    private final PhoneNumberNormalizer phoneNumberNormalizer;
    private final HomeserverRouter homeserverRouter;
    private final UserSecurityService userSecurityService;
    private final AuthFactorPolicy authFactorPolicy;
    private final MatrixProvisioningService matrixProvisioningService;
    private final MatrixAdminClient matrixAdminClient;
    private final UsernamePolicy usernamePolicy;
    private final OidcAuthorizationService authorizationService;
    private final PasskeyService passkeyService;
    private final RegistrationGuard registrationGuard;
    private final AccountLocalpartResolver accountLocalparts;
    private final AccountGenesisService accountGenesisService;
    private final AccountCreationService accountCreationService;
    private final LoginFactorEnrollmentService loginFactorEnrollmentService;
    private final AccountRecoveryService accountRecoveryService;
    private final AccountReauthService accountReauthService;
    private final TokenRevocationService tokenRevocationService;
    private final EndOtherSessionsService endOtherSessionsService;

    @GetMapping("/context")
    @Operation(summary = "Fetch the current login state", description = "Returns the current step, the login intent (PHONE or PASSKEY, from the OIDC login_hint), a CSRF token to echo on subsequent calls, the masked phone when known, and whether this is an in-app passkey enrollment. Once the step is one the flow can only reach with the subject resolved, it also reports passkeyRegistered, preferredFactor and passkeysEnabled; all are absent before then, and in particular at the phone step, where the session holds a submitted number and nothing proved. At ENROLL_STEP_UP, and only there, it additionally reports pinRegistered, so the step-up offers the PIN beside the passkey only to an account that holds one. At PIN_REQUIRED and PASSKEY_REQUIRED after an OTP it also reports recovery, the delayed account recovery state, which is absent whenever recovery is not available to this session.")
    public ResponseEntity<LoginStateResponse> context(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId) {
        LoginSession session = requireSession(sessionId);
        return ResponseEntity.ok(state(session, null));
    }

    @GetMapping({ "/enroll/{token}", "/passkey/enroll/{token}" })
    @Operation(summary = "Open the in-app factor enrollment web view", description = "One-time handoff for an already-signed-in user adding a passkey or a PIN from settings. The enrollment session is created by POST /security/passkey/enroll/start or POST /security/pin/enroll/start; the cookie set on that API call is not present in this separate web view, so this redeems the one-time token, drops the first-party login cookie, and redirects into the sign-in SPA, which finds the session at the ENROLL_STEP_UP step. The /passkey/ spelling is the path older enroll links carry and is the same handoff.")
    public ResponseEntity<Void> openPasskeyEnrollment(
            @org.springframework.web.bind.annotation.PathVariable("token") String token) {
        String sessionId = loginSessionService.consumeEnrollToken(token)
                .orElseThrow(() -> new LoginFlowException(HttpStatus.GONE, "enroll_link_expired",
                        "This passkey setup link has expired. Please try again."));
        requireSession(sessionId);

        ResponseCookie cookie = ResponseCookie.from(properties.getCookieName(), sessionId)
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite("Lax")
                .path("/")
                .maxAge(properties.getSessionTtl())
                .build();

        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .header(HttpHeaders.LOCATION, properties.getUiUrl())
                .build();
    }

    @PostMapping("/phone")
    @Operation(summary = "Submit the phone number", description = "Dispatches an OTP to the supplied phone number and advances to the OTP step.")
    public ResponseEntity<LoginStateResponse> submitPhone(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PhoneRequest request,
            HttpServletRequest servletRequest) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PHONE, Phase.OTP_SENT);

        // Normalize to canonical E.164 at the boundary, so a number typed without a country code cannot
        // key the OTP or the phone digest under a different value and mint a duplicate account.
        String phone = phoneNumberNormalizer.toE164(request.phoneNumber());
        // Web gate (inert unless enabled): runs before the SMS is sent. Native app flows are exempt.
        registrationGuard.assertOtpAllowed(session, phone);
        otpService.sendOtp(phone, servletRequest.getRemoteAddr(), request.locale());

        session.setPhoneNumber(phone);
        session.setLocale(request.locale());
        session.setPhase(Phase.OTP_SENT);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    @PostMapping("/otp")
    @Operation(summary = "Verify the OTP", description = "Verifies the one-time code, then routes a returning account to the step for the factor it holds (PIN_REQUIRED when it holds a PIN, PASSKEY_REQUIRED when it holds only a passkey, factor setup when it holds neither) and a new user to the profile step. The OTP never completes a login on its own.")
    public ResponseEntity<LoginStateResponse> submitOtp(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid OtpRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.OTP_SENT);

        otpService.verifyOtp(session.getPhoneNumber(), request.code().trim());
        // The only place this is set. Recovery is offered only to a session that proved the
        // number here, never to one that reached a factor step some other way.
        session.setOtpVerified(true);

        String digest = phoneNumberHasher.digest(session.getPhoneNumber());
        Optional<DirectoryEntry> existing = directoryService.findByDigest(digest);
        if (existing.isPresent()) {
            return routeExistingUser(sessionId, session, existing.get().getUserId(), existing.get());
        }

        // The digest missed. Check the homeserver's msisdn binding before treating this as a new signup,
        // so pepper drift cannot mint a second account.
        Optional<String> boundUserId = matrixAdminClient.findUserIdByPhone(session.getPhoneNumber());
        if (boundUserId.isPresent()) {
            String userId = boundUserId.get();
            log.warn("Directory row missing for a returning account (digest miss); recovered userId via "
                    + "homeserver phone binding and healing the directory row");
            // Heal the directory row so future logins resolve via the fast digest path.
            healDirectoryRow(digest, session.getPhoneNumber(), userId);
            rootRecoveredAccount(userId);
            // The healed row carries no stored username, so its localpart takes the MXID
            // fallback in AccountLocalpartResolver. A failed heal leaves no row at all.
            DirectoryEntry healed = directoryService.findByDigest(digest)
                    .filter(row -> userId.equals(row.getUserId()))
                    .orElse(null);
            return routeExistingUser(sessionId, session, userId, healed);
        }

        // Re-authentication is login-only: a phone that resolves to no existing account is rejected here
        // and never falls through to account creation.
        if (session.getReauthUserId() != null) {
            throw reauthMismatch();
        }

        session.setNewUser(true);
        session.setPhase(Phase.PROFILE_REQUIRED);
        issueGenesisAttachChallenge(session);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /**
     * Issues the bytes a client must sign to attach its account genesis, when a session carrying a
     * handle enters the profile step. Issued once per profile step, so a UI reload does not invalidate
     * a proof already computed. The value lives only on the server-side session and is never accepted
     * back as a lookup key.
     */
    private void issueGenesisAttachChallenge(LoginSession session) {
        if (!accountGenesisService.isEnabled()
                || !StringUtils.hasText(session.getGenesisAttachHandle())
                || StringUtils.hasText(session.getGenesisAttachChallenge())) {
            return;
        }
        session.setGenesisAttachChallenge(accountGenesisService.issueAttachChallenge());
    }

    /**
     * The handle and the challenge are read from the server-side session; only the proof comes from the
     * client. Returns {@code null} when the feature is off.
     */
    private AccountCreationService.GenesisAttachment genesisAttachment(LoginSession session, String attachProof) {
        if (!accountGenesisService.isEnabled()) {
            return null;
        }
        String nativeMarker = properties.getRegistration() == null ? null
                : properties.getRegistration().getNativeClientMarker();
        boolean nativeClient = nativeMarker != null && nativeMarker.equals(session.getDownstreamClient());
        return new AccountCreationService.GenesisAttachment(
                session.getGenesisAttachHandle(),
                session.getGenesisAttachChallenge(),
                attachProof,
                nativeClient);
    }

    /**
     * Routes a returning user whose phone was just proved to the step for the factor the account holds.
     * Marks the session as an existing user and emits the stored localpart, which MAS imports as
     * {@code preferred_username}. The localpart is read from the directory row, never derived from
     * {@code userId}; see {@link AccountLocalpartResolver}.
     *
     * @param entry the account's directory row, or {@code null} when none is stored
     */
    private ResponseEntity<LoginStateResponse> routeExistingUser(
            String sessionId, LoginSession session, String userId, DirectoryEntry entry) {
        // On a re-authentication the verified phone must belong to the already-authenticated user.
        if (session.getReauthUserId() != null && !session.getReauthUserId().equals(userId)) {
            throw reauthMismatch();
        }
        // Resolve the localpart before touching the session, so a refusal leaves nothing saved.
        String preferredUsername = accountLocalparts.forExistingAccount(userId,
                entry != null ? List.of(entry) : List.of());
        session.setUserId(userId);
        session.setDisplayName(entry != null ? entry.getDisplayName() : null);
        session.setPreferredUsername(preferredUsername);
        session.setNewUser(false);
        // Reads the stored credentials, so switching passkeys off on a deployment never turns a
        // passkey-only account into one this OTP could finish by setting a PIN.
        AuthFactorPolicy.LoginPolicy policy = authFactorPolicy.loginPolicy(userId);
        if (policy.pinStepRequired()) {
            session.setPhase(Phase.PIN_REQUIRED);
            loginSessionService.save(sessionId, session);
            return ResponseEntity.ok(state(session, null));
        }
        if (policy.passkeyRequired()) {
            session.setPhase(Phase.PASSKEY_REQUIRED);
            loginSessionService.save(sessionId, session);
            return ResponseEntity.ok(state(session, null));
        }
        // An account holding no factor is offered the passkey and must set a PIN if it declines. It does
        // not finish on the OTP.
        return offerPasskeyBeforePin(sessionId, session);
    }

    /**
     * Re-binds the phone digest to an existing MXID after the directory row was orphaned. Best-effort:
     * a failure is logged and must not block a returning user from signing in.
     */
    private void healDirectoryRow(String digest, String phone, String userId) {
        try {
            String maskedPhone = phoneNumberMasker.mask(phone);
            // Null displayName preserves any existing value (none here, since the row
            // was missing) without clobbering it.
            directoryService.upsertByDigest(digest, maskedPhone, userId, null);
        } catch (RuntimeException ex) {
            log.warn("Failed to heal directory row for recovered account: {}", ex.getMessage());
        }
    }

    /**
     * Gives an account recovered through the homeserver phone binding the genesis row it never had.
     * Best-effort and idempotent: a failure must not block sign-in, and the next backfill run picks up
     * a missed account.
     */
    private void rootRecoveredAccount(String userId) {
        if (!accountGenesisService.isEnabled()) {
            return;
        }
        try {
            accountGenesisService.bootstrap(userId);
        } catch (RuntimeException ex) {
            log.warn("Could not root a recovered account in a genesis row: {}", ex.getMessage());
        }
    }

    @PostMapping("/pin")
    @Operation(summary = "Verify the account PIN", description = "Second factor for returning users with two-step verification. Completes login on success; lockout policy applies.")
    public ResponseEntity<LoginStateResponse> submitPin(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PinRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PIN_REQUIRED);

        userSecurityService.validatePinOrThrow(session.getUserId(), request.pin().trim());
        session.setAuthenticatedFactor(SessionFactor.PIN);
        return advanceToPasskeySetup(sessionId, session);
    }

    @PostMapping("/profile")
    @Operation(summary = "Choose username and display name", description = "Finalizes a brand-new account: validates the username, reserves the handle, and offers passkey enrollment. Falls through to the PIN setup step only on a deployment with passkeys switched off.")
    public ResponseEntity<LoginStateResponse> submitProfile(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid ProfileRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PROFILE_REQUIRED);
        // Invite-only gate for web signups (inert unless enabled). Only the new-user branch reaches here.
        registrationGuard.assertAllowedForNewUser(session);

        String localpart = usernamePolicy.normalizeAndValidate(request.username());
        // Username uniqueness is enforced within this deployment's directory, not federation-wide.
        if (directoryService.isUsernameTaken(localpart)) {
            throw new UsernameTakenException("Username already taken");
        }

        Homeserver homeserver = homeserverRouter
                .selectForNewAccount(AccountPlacementContext.forPhone(session.getPhoneNumber()));
        if (matrixAdminClient.userExists(matrixProvisioningService.buildUserId(localpart, homeserver))) {
            throw new UsernameTakenException("Username already taken");
        }

        // sub, the directory entry and preferred_username are all built from the same localpart.
        String userId = matrixProvisioningService.buildUserId(localpart, homeserver);
        String displayName = StringUtils.hasText(request.displayName()) ? request.displayName().trim() : localpart;
        String digest = phoneNumberHasher.digest(session.getPhoneNumber());
        String maskedPhone = phoneNumberMasker.mask(session.getPhoneNumber());
        try {
            // The directory row, the routing choice and the accountId are written in one transaction. A
            // presented handle that fails to attach rolls the whole signup back instead of downgrading to a
            // bootstrap id.
            accountCreationService.createAccount(digest, maskedPhone, userId, displayName, homeserver.id(),
                    localpart, genesisAttachment(session, request.attachProof()));
        } catch (DataIntegrityViolationException ex) {
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        // Cleared only after a successful attach, so a failed proof can be retried in this session.
        session.setGenesisAttachHandle(null);
        session.setGenesisAttachChallenge(null);
        session.setUserId(userId);
        session.setDisplayName(displayName);
        session.setPreferredUsername(localpart);
        // A new account is offered the passkey first and reaches the PIN step only when it cannot have one.
        session.setNewUser(true);
        return offerPasskeyBeforePin(sessionId, session);
    }

    @PostMapping("/pin-setup")
    @Operation(summary = "Set the account PIN", description = "Two ways in. During a sign-in it is the factor for an account that holds none and is not finishing with a passkey: a new account, or an older one that never set a factor, reached by declining the passkey offer or directly on a deployment with passkeys switched off. In an enrollment session started at POST /security/pin/enroll/start it is the PIN being added from settings, and it is reachable only once that session has been through ENROLL_STEP_UP. Either way it cannot be skipped: skip:true, a missing PIN and a blank PIN are all 400 pin_required. 409 factor_required when a signing-in account gained a factor from another session in the meantime, 409 pin_already_set when an enrolling one gained a PIN.")
    public ResponseEntity<LoginStateResponse> submitPinSetup(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PinSetupRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PIN_SETUP);
        requireEnrollStepUpDone(session);

        // Mandatory: skipping would finish a sign-in on the phone OTP alone.
        if (request.skip() || !StringUtils.hasText(request.pin())) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "pin_required",
                    "Choose a PIN to protect your account.");
        }
        if (session.isEnroll()) {
            // Adding a PIN from settings: no sign-in is being finished, so no factor is recorded on the
            // session and no authorization code follows.
            loginFactorEnrollmentService.setUpEnrolledPin(session.getUserId(), request.pin().trim());
            return completeEnrollment(sessionId, session);
        }
        // Refused under the row lock when the account already holds a factor, so a second
        // session for the same factorless account cannot add its own PIN to an account the first
        // one has just secured.
        loginFactorEnrollmentService.setUpFirstPin(session.getUserId(), request.pin().trim());
        session.setAuthenticatedFactor(SessionFactor.ENROLLED);
        // The passkey was already offered before this step. Routing back to the offer would loop.
        return complete(sessionId, session);
    }

    @PostMapping("/passkey/register/options")
    @Operation(summary = "Start passkey setup", description = "Creates WebAuthn registration options after phone verification and any PIN step are complete.")
    public ResponseEntity<PasskeyOptionsResponse> startPasskeyRegistration(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PASSKEY_SETUP);
        requireEnrollStepUpDone(session);

        return ResponseEntity.ok(new PasskeyOptionsResponse(passkeyService.startRegistration(sessionId, session)));
    }

    @PostMapping("/passkey/register/verify")
    @Operation(summary = "Finish passkey setup", description = "Verifies the WebAuthn attestation response and stores the credential for future passkey sign-ins.")
    public ResponseEntity<LoginStateResponse> finishPasskeyRegistration(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PasskeyCredentialRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PASSKEY_SETUP);
        requireEnrollStepUpDone(session);

        if (session.isEnroll()) {
            // Bearer-authenticated handoff from settings: no sign-in is being finished here.
            passkeyService.finishRegistration(sessionId, session, request.credential());
            return completeEnrollment(sessionId, session);
        }
        boolean firstFactor = loginFactorEnrollmentService.registerPasskey(sessionId, session, request.credential());
        if (firstFactor && session.getAuthenticatedFactor() == null) {
            session.setAuthenticatedFactor(SessionFactor.ENROLLED);
        }
        return complete(sessionId, session);
    }

    @PostMapping("/passkey/setup-skip")
    @Operation(summary = "Continue without a passkey", description = "Leaves the passkey offer without registering one, whether the user declined it, the ceremony failed, or the device has no authenticator to run it. A session that already signed in with a factor (a PIN sign-in offered a passkey afterwards) completes; an account holding no factor, new or old, goes on to the mandatory PIN setup step.")
    public ResponseEntity<LoginStateResponse> skipPasskeySetup(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PASSKEY_SETUP);

        if (session.isEnroll()) {
            return completeEnrollment(sessionId, session);
        }
        // A session that already authenticated with a factor was only being offered an extra
        // one, so declining it finishes the sign-in it had already earned.
        if (session.getAuthenticatedFactor() != null) {
            return complete(sessionId, session);
        }
        // An account with no factor. Declined, refused by the authenticator or impossible on this device
        // all go on to the PIN step: the PIN is being set on an account with no factor, not accepted in
        // place of one.
        return advanceToPinSetup(sessionId, session);
    }

    @PostMapping("/passkey/auth/options")
    @Operation(summary = "Start passkey sign-in", description = "Begins a passkey assertion, letting a returning user with a registered passkey sign in without an OTP. Available from the phone and OTP steps, from the PIN step, so a user who has already been asked for their PIN can still reach the stronger factor, and from PASSKEY_REQUIRED. Never available at the profile step, which belongs to an account that does not exist yet, and never in a passkey-enrollment session. Only ever resolves to a pre-existing account.")
    public ResponseEntity<PasskeyOptionsResponse> startPasskeyAuthentication(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        refuseEnrollmentSignIn(session);
        requireAssertionPhase(session);

        return ResponseEntity.ok(new PasskeyOptionsResponse(passkeyService.startAuthentication(sessionId)));
    }

    @PostMapping("/passkey/auth/verify")
    @Operation(summary = "Finish passkey sign-in", description = "Verifies the WebAuthn assertion and, only when it resolves to an existing OTP-registered account with a phone on file, completes login, intentionally bypassing the steps that would otherwise remain. A session that has already resolved its subject, which is every session at PIN_REQUIRED and PASSKEY_REQUIRED, additionally requires the assertion to resolve to that same account. Never creates an account.")
    public ResponseEntity<LoginStateResponse> finishPasskeyAuthentication(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PasskeyCredentialRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        refuseEnrollmentSignIn(session);
        requireAssertionPhase(session);

        PasskeyService.PasskeyAuthentication auth = passkeyService.finishAuthentication(sessionId, request.credential());
        String userId = auth.userId();

        // A session that already resolved its subject keeps it: an assertion resolving to a different
        // account is refused before anything is accepted and before the directory is read.
        if (StringUtils.hasText(session.getUserId()) && !session.getUserId().equals(userId)) {
            throw new LoginFlowException(HttpStatus.FORBIDDEN, "passkey_user_mismatch",
                    "This passkey belongs to a different account.");
        }

        // Passkey sign-in may bypass OTP only for an existing account with a directory row. The row is
        // phone-keyed, so its presence proves OTP registration. This path must never create an account,
        // set newUser or reach PROFILE_REQUIRED.
        DirectoryEntry entry = directoryService.findByUserId(userId).stream()
                .filter(e -> StringUtils.hasText(e.getPhoneDigest()))
                .findFirst()
                .orElseThrow(() -> new LoginFlowException(HttpStatus.FORBIDDEN, "passkey_user_not_registered",
                        "This passkey is not linked to a registered account."));

        // On a re-authentication the asserted credential must belong to the existing subject.
        if (session.getReauthUserId() != null && !session.getReauthUserId().equals(userId)) {
            throw reauthMismatch();
        }

        String preferredUsername = accountLocalparts.forExistingAccount(userId, List.of(entry));
        session.setUserId(userId);
        session.setDisplayName(entry.getDisplayName());
        session.setPreferredUsername(preferredUsername);
        session.setNewUser(false);
        // Intentional OTP bypass: a proven existing user signs in straight through.
        session.setAuthenticatedFactor(SessionFactor.PASSKEY);
        return complete(sessionId, session);
    }

    // --- In-app factor enrollment: the step-up that comes before anything is stored ---

    @PostMapping("/enroll/stepup/passkey/options")
    @Operation(summary = "Start the enrollment step-up with a passkey", description = "Begins a user-verifying WebAuthn assertion for an enrollment session at ENROLL_STEP_UP. The preferred proof for an account that holds a passkey, and the only one asked for: an account that produces a passkey is never also asked for its PIN. The ceremony is pinned to the session's account and lives in the step-up namespace, so it can neither complete a sign-in nor be answered by another account's credential.")
    public ResponseEntity<PasskeyOptionsResponse> startEnrollStepUpPasskey(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requireEnrollStepUp(session);

        return ResponseEntity.ok(new PasskeyOptionsResponse(
                passkeyService.startStepUpAssertion(sessionId, session.getUserId())));
    }

    @PostMapping("/enroll/stepup/passkey/verify")
    @Operation(summary = "Finish the enrollment step-up with a passkey", description = "Verifies the assertion, which must verify the user and must resolve to this session's account, and moves the session to the setup step for the factor being added.")
    public ResponseEntity<LoginStateResponse> finishEnrollStepUpPasskey(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PasskeyCredentialRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requireEnrollStepUp(session);

        PasskeyService.PasskeyAuthentication auth =
                passkeyService.finishStepUpAssertion(sessionId, request.credential());
        // The ceremony was pinned to this account, so a credential from another one cannot have
        // answered it; checked anyway, because this is the proof a factor is about to be stored on.
        if (!session.getUserId().equals(auth.userId())) {
            throw new LoginFlowException(HttpStatus.FORBIDDEN, "passkey_user_mismatch",
                    "This passkey belongs to a different account.");
        }
        return acceptEnrollStepUp(sessionId, session, AuthFactor.PASSKEY);
    }

    @PostMapping("/enroll/stepup/pin")
    @Operation(summary = "Finish the enrollment step-up with the account PIN", description = "The proof for an account that holds a PIN and no passkey to produce. Counted and locked out exactly like the PIN step of a sign-in.")
    public ResponseEntity<LoginStateResponse> submitEnrollStepUpPin(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PinRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requireEnrollStepUp(session);
        if (!authFactorPolicy.pinRegistered(session.getUserId())) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "pin_not_set",
                    "This account has no PIN to confirm with.");
        }

        userSecurityService.validatePinOrThrow(session.getUserId(), request.pin().trim());
        return acceptEnrollStepUp(sessionId, session, AuthFactor.PIN);
    }

    @PostMapping("/enroll/stepup/otp/send")
    @Operation(summary = "Send the enrollment step-up code", description = "Only for an account that holds no factor at all, which has nothing stronger to prove itself with. The caller confirms the number on their own account: it is digested and compared with that account's own directory binding exactly as POST /account/reauth/start does, and only a match sends a code, to that number. 403 reauth_phone_mismatch otherwise, in the same words whoever the number belongs to. An account that holds a passkey or a PIN is refused here (409 step_up_factor_available), because an SMS code must never establish a factor on an account that already has a stronger one.")
    public ResponseEntity<LoginStateResponse> sendEnrollStepUpOtp(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PhoneRequest request,
            HttpServletRequest servletRequest) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requireEnrollStepUp(session);
        requireNoStrongerFactor(session);

        accountReauthService.startReauth(session.getUserId(), request.phoneNumber(),
                servletRequest.getRemoteAddr(), request.locale());
        // Nothing is recorded: the number is submitted again with the code, and checked again
        // the same way, so this step leaves no state behind for the next one to trust.
        return ResponseEntity.ok(state(session, null));
    }

    @PostMapping("/enroll/stepup/otp/verify")
    @Operation(summary = "Finish the enrollment step-up with the code", description = "Redeems the code sent to the account's own number, re-checking the number the same way, and moves the session to the setup step. This is the reauthentication an account holding no factor does before its first strong factor: it establishes a LOGIN factor and nothing else.")
    public ResponseEntity<LoginStateResponse> verifyEnrollStepUpOtp(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid EnrollStepUpOtpRequest request,
            HttpServletRequest servletRequest) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requireEnrollStepUp(session);
        requireNoStrongerFactor(session);

        accountReauthService.verifyPhoneOtp(session.getUserId(), request.phoneNumber(), request.code().trim(),
                Phase.ENROLL_STEP_UP.name(), servletRequest.getRemoteAddr());
        return acceptEnrollStepUp(sessionId, session, AuthFactor.PHONE_OTP);
    }

    @PostMapping("/recovery/start")
    @Operation(summary = "Start a delayed account recovery", description = "For a user who proved the phone number by OTP but cannot present the PIN or passkey the account holds. Available only at PIN_REQUIRED or PASSKEY_REQUIRED after an OTP, never in a re-authentication or an enrollment session (409 recovery_unavailable). Opens a recovery episode when the account has had no completed sign-in for the dormancy period, and returns the login state with recovery.status PENDING; a live episode is returned unchanged. 400 recovery_cooldown_active with retryAfterSeconds and Retry-After when the account was used too recently. Sends no SMS. Every signed-in app can cancel the episode, and signing in with the PIN or a passkey ends it.")
    public ResponseEntity<LoginStateResponse> startRecovery(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            HttpServletRequest servletRequest) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requireRecoveryAvailable(session);

        accountRecoveryService.start(session.getUserId(), phoneNumberMasker.mask(session.getPhoneNumber()),
                servletRequest.getRemoteAddr());
        return ResponseEntity.ok(state(session, null));
    }

    @PostMapping("/recovery/complete")
    @Operation(summary = "Complete a delayed account recovery", description = "Sets the new PIN once the recovery's wait is over, removes the account's passkeys, and completes the login. Re-checked under the account row lock: 409 recovery_not_ready with the fresh recovery object when the episode is still waiting, was cancelled or has expired. A malformed or weak PIN is 400 invalid_pin or weak_pin and counts nothing. The issued ID token carries gua_end_other_sessions=true, which the authentication service acts on by signing out every other session.")
    public ResponseEntity<LoginStateResponse> completeRecovery(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody RecoveryCompleteRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requireRecoveryAvailable(session);

        String newPin = request == null || request.newPin() == null ? null : request.newPin().trim();
        accountRecoveryService.complete(session.getUserId(), newPin);
        // Revokes this service's own access tokens. The authentication service ends the app sessions on
        // the claim this login carries. The commit recorded that sign-out as owed, so if anything fails
        // from here on, the account's next completed sign-in carries the claim instead.
        tokenRevocationService.revokeAllTokens(session.getUserId());
        session.setAuthenticatedFactor(SessionFactor.RECOVERY);
        return complete(sessionId, session);
    }

    /**
     * Issues the authorization code, consumes the login session, clears its cookie and hands the UI
     * the redirect URL back to the requesting client. Refuses a session that has not authenticated
     * with a factor, so no route can finish a sign-in on the phone OTP alone.
     */
    private ResponseEntity<LoginStateResponse> complete(String sessionId, LoginSession session) {
        if (session.getAuthenticatedFactor() == null) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "factor_required",
                    "Sign in with your PIN or passkey to continue.");
        }
        userSecurityService.recordSuccessfulLogin(session.getUserId());

        // Only a completed recovery asks the authentication service to end every other session of the
        // account: this one, or an earlier one whose sign-out is still owed.
        boolean endOtherSessions = session.getAuthenticatedFactor() == SessionFactor.RECOVERY
                || endOtherSessionsService.isOwed(session.getUserId());
        if (endOtherSessions && session.getAuthenticatedFactor() != SessionFactor.RECOVERY) {
            log.warn("Sign-in for user {} carries the sign-out of other sessions still owed by its recovery",
                    session.getUserId());
        }
        OidcAuthorization authorization = new OidcAuthorization(
                session.getUserId(),
                session.getPhoneNumber(),
                session.getDisplayName(),
                session.getPreferredUsername(),
                new LinkedHashSet<>(session.getScope()),
                session.getClientId(),
                session.getNonce(),
                endOtherSessions);
        OidcAuthorizationCode code = authorizationService.issueCode(
                authorization, session.getRedirectUri(), session.getCodeChallenge());

        UriComponentsBuilder redirect = UriComponentsBuilder.fromUriString(session.getRedirectUri())
                .queryParam("code", code.code());
        if (session.getState() != null) {
            redirect.queryParam("state", session.getState());
        }

        session.setPhase(Phase.COMPLETED);
        loginSessionService.delete(sessionId);

        ResponseCookie expired = ResponseCookie.from(properties.getCookieName(), "")
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, expired.toString())
                .body(state(session, redirect.toUriString()));
    }

    /**
     * Terminal step for in-app passkey enrollment (entered via
     * {@code POST /security/passkey/enroll/start}). There is no OIDC authorization in flight, so this
     * issues no authorization code. It finalizes the session, clears the cookie and hands the web view
     * the app-scheme redirect it was opened against, which closes the client's auth session.
     */
    private ResponseEntity<LoginStateResponse> completeEnrollment(String sessionId, LoginSession session) {
        session.setPhase(Phase.COMPLETED);
        loginSessionService.delete(sessionId);

        ResponseCookie expired = ResponseCookie.from(properties.getCookieName(), "")
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();

        // An app-scheme redirect with no OIDC error is the client's success signal.
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, expired.toString())
                .body(state(session, session.getRedirectUri()));
    }

    /**
     * Factor routing for an account that holds none: offer the passkey, and fall back to the PIN step
     * only when this deployment cannot run a passkey ceremony. The fallback is read from configuration,
     * never from a client claim. A client that cannot use a passkey declines at
     * {@code POST /login/passkey/setup-skip}, which lands on the same PIN step.
     */
    private ResponseEntity<LoginStateResponse> offerPasskeyBeforePin(String sessionId, LoginSession session) {
        if (!authFactorPolicy.passkeysSupported()) {
            return advanceToPinSetup(sessionId, session);
        }
        session.setPhase(Phase.PASSKEY_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /**
     * The PIN setup step. Reached from exactly two places: the passkey offer left without a credential,
     * and a deployment that has no passkeys to offer.
     */
    private ResponseEntity<LoginStateResponse> advanceToPinSetup(String sessionId, LoginSession session) {
        session.setPhase(Phase.PIN_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    private ResponseEntity<LoginStateResponse> advanceToPasskeySetup(String sessionId, LoginSession session) {
        // Reached only after a PIN sign-in. Skip the passkey offer when the account already has one or
        // the deployment cannot run a ceremony.
        if (!authFactorPolicy.passkeysSupported() || authFactorPolicy.passkeyHeld(session.getUserId())) {
            return complete(sessionId, session);
        }
        session.setPhase(Phase.PASSKEY_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /**
     * Single rejection for a re-authentication whose verified phone is unregistered or belongs to a
     * different user. Deliberately generic so it does not reveal whether the phone exists.
     */
    private static LoginFlowException reauthMismatch() {
        return new LoginFlowException(HttpStatus.FORBIDDEN, "reauth_user_mismatch",
                "This phone number is not associated with your account.");
    }

    private LoginSession requireSession(String sessionId) {
        return loginSessionService.find(sessionId)
                .orElseThrow(() -> new LoginFlowException(HttpStatus.GONE, "login_session_expired",
                        "Your login session has expired. Please start again."));
    }

    private void requireCsrf(LoginSession session, String csrf) {
        if (session.getCsrfToken() == null || csrf == null
                || !constantTimeEquals(session.getCsrfToken(), csrf)) {
            throw new LoginFlowException(HttpStatus.FORBIDDEN, "csrf_failed", "Invalid or missing CSRF token");
        }
    }

    /**
     * The steps a sign-in assertion may be presented from. {@code PROFILE_REQUIRED} must stay excluded:
     * that step belongs to a session that matched no account, so an assertion accepted there would
     * reach account creation. {@code PASSKEY_SETUP} is excluded because it is the registration ceremony.
     */
    private void requireAssertionPhase(LoginSession session) {
        requirePhase(session, Phase.PHONE, Phase.OTP_SENT, Phase.PIN_REQUIRED, Phase.PASSKEY_REQUIRED);
    }

    /**
     * Keeps an in-app enrollment session out of the sign-in ceremony. It carries no OIDC request and
     * must never reach {@link #complete}; it has only {@link #completeEnrollment}.
     */
    private void refuseEnrollmentSignIn(LoginSession session) {
        if (session.isEnroll()) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "enroll_session_cannot_sign_in",
                    "This session is for adding a passkey, not for signing in.");
        }
    }

    /**
     * The gate on every enrollment step-up endpoint: an enrollment session, sitting at the step
     * where it has yet to prove anything, with its account resolved.
     */
    private void requireEnrollStepUp(LoginSession session) {
        if (!session.isEnroll()) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "unexpected_step",
                    "This step belongs to adding a factor from your account settings.");
        }
        requirePhase(session, Phase.ENROLL_STEP_UP);
        if (!StringUtils.hasText(session.getUserId())) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "enroll_user_unknown",
                    "This setup session is not bound to an account.");
        }
    }

    /**
     * The SMS proof is only for an account that holds no factor. An account holding a passkey or a PIN
     * must produce it; otherwise it would be only as strong as its SIM.
     */
    private void requireNoStrongerFactor(LoginSession session) {
        if (!authFactorPolicy.loginPolicy(session.getUserId()).factorSetupRequired()) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "step_up_factor_available",
                    "Confirm with the passkey or PIN on this account.");
        }
    }

    /**
     * Records the proof on the session and moves it to the setup step for the factor it was opened to
     * add. Sets {@code enrollStepUpFactor}, never {@code authenticatedFactor}: an enrollment session
     * must not be able to finish a sign-in.
     */
    private ResponseEntity<LoginStateResponse> acceptEnrollStepUp(String sessionId, LoginSession session,
            AuthFactor provedWith) {
        session.setEnrollStepUpFactor(provedWith);
        session.setPhase(session.getEnrollTarget() == LoginSession.EnrollTarget.PIN
                ? Phase.PIN_SETUP
                : Phase.PASSKEY_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /**
     * Refuses to store a factor for an enrollment session that has not been through the step-up.
     * A bearer token alone must never add a durable factor.
     */
    private void requireEnrollStepUpDone(LoginSession session) {
        if (session.isEnroll() && session.getEnrollStepUpFactor() == null) {
            throw new StepUpRequiredException(
                    "Confirm it is you before adding a way to sign in.");
        }
    }

    /**
     * Whether this session may be offered the delayed account recovery. Requires all of: the OTP proved
     * the number, the subject is resolved, the step asks for a factor the account holds, and the
     * session is neither a re-authentication nor an enrollment.
     */
    private boolean recoveryAvailable(LoginSession session) {
        return session.isOtpVerified()
                && StringUtils.hasText(session.getUserId())
                && RECOVERY_PHASES.contains(session.getPhase())
                && session.getReauthUserId() == null
                && !session.isEnroll();
    }

    private void requireRecoveryAvailable(LoginSession session) {
        if (!recoveryAvailable(session)) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "recovery_unavailable",
                    "Account recovery is not available from this step.");
        }
    }

    private void requirePhase(LoginSession session, Phase... allowed) {
        for (Phase phase : allowed) {
            if (session.getPhase() == phase) {
                return;
            }
        }
        throw new LoginFlowException(HttpStatus.CONFLICT, "unexpected_step",
                "This step is not valid for the current login state");
    }

    private LoginStateResponse state(LoginSession session, String redirectUrl) {
        AuthFactorPolicy.RegisteredFactors factors = publishableFactors(session);
        AccountRecoveryState recovery = recoveryAvailable(session)
                ? accountRecoveryService.stateFor(session.getUserId())
                : null;
        return new LoginStateResponse(
                session.getPhase().name(),
                session.getIntent().name(),
                session.getClientId(),
                maskPhone(session.getPhoneNumber()),
                session.getPhoneHint(),
                session.getCsrfToken(),
                session.isNewUser(),
                redirectUrl,
                session.getGenesisAttachChallenge(),
                factors == null ? null : factors.passkey(),
                publishablePin(session, factors),
                factors == null ? null : factors.preferred().name(),
                factors == null ? null : authFactorPolicy.passkeysSupported(),
                session.isEnroll(),
                recovery);
    }

    /**
     * What this session may say about the account's registered factors, or {@code null} when it may
     * say nothing (the default). The phase must be in {@link #FACTOR_REPORT_PHASES} and the session
     * must carry the resolved subject, so the answer is keyed by who the caller proved to be and never
     * by the phone number they typed.
     */
    private AuthFactorPolicy.RegisteredFactors publishableFactors(LoginSession session) {
        if (!FACTOR_REPORT_PHASES.contains(session.getPhase()) || !StringUtils.hasText(session.getUserId())) {
            return null;
        }
        return authFactorPolicy.registeredFactors(session.getUserId());
    }

    /**
     * Whether the account holds a PIN, published at the enrollment step-up and nowhere else. The web UI
     * needs it to decide whether to offer the PIN beside the passkey. It discloses nothing new there:
     * the session was minted from the caller's own bearer token, and {@code GET /security/pin/status}
     * already reports {@code hasPin} to that caller.
     */
    private Boolean publishablePin(LoginSession session, AuthFactorPolicy.RegisteredFactors factors) {
        return factors == null || session.getPhase() != Phase.ENROLL_STEP_UP ? null : factors.pin();
    }

    private static String maskPhone(String phone) {
        if (phone == null || phone.length() < 4) {
            return null;
        }
        return "\u2022\u2022\u2022\u2022" + phone.substring(phone.length() - 4);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    // --- Request / response payloads ---

    public record PhoneRequest(@NotBlank String phoneNumber, String locale) {
    }

    public record OtpRequest(@NotBlank String code) {
    }

    public record PinRequest(@NotBlank String pin) {
    }

    /**
     * PIN setup is mandatory. {@code skip} is still accepted on the wire so an older client gets
     * a {@code pin_required} answer instead of a malformed-request one.
     */
    public record PinSetupRequest(String pin, boolean skip) {
    }

    public record RecoveryCompleteRequest(String newPin) {
    }

    /**
     * {@code attachProof} is the client's Ed25519 signature, base64url, over the attach-proof domain,
     * the challenge this session was issued, and the raw accountId bytes. Absent for a signup that is
     * not attaching a genesis, which takes the bootstrap branch and is not a failure.
     */
    public record ProfileRequest(@NotBlank String username, String displayName, String attachProof) {
    }

    public record PasskeyCredentialRequest(@NotNull JsonNode credential) {
    }

    /** The account's own number again, with the code sent to it, at the enrollment step-up. */
    public record EnrollStepUpOtpRequest(@NotBlank String phoneNumber, @NotBlank String code) {
    }

    public record PasskeyOptionsResponse(JsonNode publicKey) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LoginStateResponse(
            String phase,
            /** PHONE or PASSKEY. Clients that predate the field treat it as PHONE. */
            String intent,
            String clientId,
            String maskedPhone,
            String phoneHint,
            String csrfToken,
            boolean newUser,
            String redirectUrl,
            /**
             * The 32 server-chosen bytes, base64url, the client must sign to attach its account genesis.
             * Null and omitted from the JSON unless this session is attaching one.
             */
            String genesisAttachChallenge,
            /**
             * Whether the resolved account holds a registered passkey. Server truth about registration: it
             * does not say the credential works on this device. Null and omitted until the session has
             * proved whose account it is.
             */
            Boolean passkeyRegistered,
            /**
             * Whether the resolved account holds a PIN. Published at {@code ENROLL_STEP_UP} only; null and
             * omitted everywhere else.
             */
            Boolean pinRegistered,
            /**
             * The strongest factor the resolved account holds: {@code PASSKEY}, {@code PIN} or
             * {@code PHONE_OTP}. Null and omitted under the same conditions as {@code passkeyRegistered}.
             */
            String preferredFactor,
            /**
             * Whether this deployment can run a passkey ceremony at all. Deployment capability, not
             * account state.
             */
            Boolean passkeysEnabled,
            /**
             * Whether this session is an in-app passkey enrollment started from settings rather
             * than a sign-in, so the UI can tell the two apart after a reload.
             */
            boolean enrollment,
            /**
             * The delayed account recovery state for this account. Always present, as an explicit
             * {@code null} when recovery is not available to this session, which tells the UI to hide the
             * recovery link.
             */
            @JsonInclude(JsonInclude.Include.ALWAYS) AccountRecoveryState recovery) {
    }
}
