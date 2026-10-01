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

/** An authorization code is issued only to a session that authenticated with a factor. */
@RestController
@RequestMapping("/login")
@Validated
@RequiredArgsConstructor
@Tag(name = "Interactive Login", description = "Browser-driven OIDC login flow (phone, OTP, PIN/profile) used by gua-idp-web")
public class LoginFlowController {

    private static final Logger log = LoggerFactory.getLogger(LoginFlowController.class);

    private static final String CSRF_HEADER = "X-CSRF-Token";
    private static final String COOKIE_NAME_EXPR = "${idp.login.cookie-name:gua_login}";

    // Allow list of steps that may report the account's factors. Earlier steps would let any caller probe a
    // phone number.
    private static final Set<Phase> FACTOR_REPORT_PHASES = EnumSet.of(Phase.PIN_REQUIRED, Phase.PASSKEY_REQUIRED,
            Phase.PIN_SETUP, Phase.PASSKEY_SETUP, Phase.ENROLL_STEP_UP);

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

        String phone = phoneNumberNormalizer.toE164(request.phoneNumber());
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
            healDirectoryRow(digest, session.getPhoneNumber(), userId);
            rootRecoveredAccount(userId);
            DirectoryEntry healed = directoryService.findByDigest(digest)
                    .filter(row -> userId.equals(row.getUserId()))
                    .orElse(null);
            return routeExistingUser(sessionId, session, userId, healed);
        }

        // Reauthentication is login-only: an unknown phone is rejected here, never sent to account creation.
        if (session.getReauthUserId() != null) {
            throw reauthMismatch();
        }

        session.setNewUser(true);
        session.setPhase(Phase.PROFILE_REQUIRED);
        issueGenesisAttachChallenge(session);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /** Issued once per profile step, so a UI reload does not invalidate a proof already computed. */
    private void issueGenesisAttachChallenge(LoginSession session) {
        if (!accountGenesisService.isEnabled()
                || !StringUtils.hasText(session.getGenesisAttachHandle())
                || StringUtils.hasText(session.getGenesisAttachChallenge())) {
            return;
        }
        session.setGenesisAttachChallenge(accountGenesisService.issueAttachChallenge());
    }

    /** Returns null when the feature is off. */
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

    /** The localpart is read from the directory row, never derived from the userId. */
    private ResponseEntity<LoginStateResponse> routeExistingUser(
            String sessionId, LoginSession session, String userId, DirectoryEntry entry) {
        // On reauthentication the verified phone must belong to the already-authenticated user.
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
        // Reads the stored credentials, so switching passkeys off never lets an OTP finish a passkey-only
        // account.
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
        // An account holding no factor must set one. It does not finish on the OTP.
        return offerPasskeyBeforePin(sessionId, session);
    }

    /** Best-effort: a failure must not block a returning user from signing in. */
    private void healDirectoryRow(String digest, String phone, String userId) {
        try {
            String maskedPhone = phoneNumberMasker.mask(phone);
            directoryService.upsertByDigest(digest, maskedPhone, userId, null);
        } catch (RuntimeException ex) {
            log.warn("Failed to heal directory row for recovered account: {}", ex.getMessage());
        }
    }

    /** Best-effort and idempotent. The next backfill run picks up a missed account. */
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
        registrationGuard.assertAllowedForNewUser(session);

        String localpart = usernamePolicy.normalizeAndValidate(request.username());
        // Unique within this deployment's directory only, not federation-wide.
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
            loginFactorEnrollmentService.setUpEnrolledPin(session.getUserId(), request.pin().trim());
            return completeEnrollment(sessionId, session);
        }
        // Refused under the row lock when the account already holds a factor.
        loginFactorEnrollmentService.setUpFirstPin(session.getUserId(), request.pin().trim());
        session.setAuthenticatedFactor(SessionFactor.ENROLLED);
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
        if (session.getAuthenticatedFactor() != null) {
            return complete(sessionId, session);
        }
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

        if (StringUtils.hasText(session.getUserId()) && !session.getUserId().equals(userId)) {
            throw new LoginFlowException(HttpStatus.FORBIDDEN, "passkey_user_mismatch",
                    "This passkey belongs to a different account.");
        }

        // Passkey sign-in may bypass OTP only for an existing account with a directory row.
        // This path must never create an account.
        DirectoryEntry entry = directoryService.findByUserId(userId).stream()
                .filter(e -> StringUtils.hasText(e.getPhoneDigest()))
                .findFirst()
                .orElseThrow(() -> new LoginFlowException(HttpStatus.FORBIDDEN, "passkey_user_not_registered",
                        "This passkey is not linked to a registered account."));

        if (session.getReauthUserId() != null && !session.getReauthUserId().equals(userId)) {
            throw reauthMismatch();
        }

        String preferredUsername = accountLocalparts.forExistingAccount(userId, List.of(entry));
        session.setUserId(userId);
        session.setDisplayName(entry.getDisplayName());
        session.setPreferredUsername(preferredUsername);
        session.setNewUser(false);
        session.setAuthenticatedFactor(SessionFactor.PASSKEY);
        return complete(sessionId, session);
    }

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
        // Revokes this service's own tokens. The authentication service ends the app sessions via the claim on
        // this login.
        tokenRevocationService.revokeAllTokens(session.getUserId());
        session.setAuthenticatedFactor(SessionFactor.RECOVERY);
        return complete(sessionId, session);
    }

    /** Refuses a session that has not authenticated with a factor. */
    private ResponseEntity<LoginStateResponse> complete(String sessionId, LoginSession session) {
        if (session.getAuthenticatedFactor() == null) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "factor_required",
                    "Sign in with your PIN or passkey to continue.");
        }
        userSecurityService.recordSuccessfulLogin(session.getUserId());

        // Only a completed recovery asks the authentication service to end every other session.
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

    /** The PIN fallback depends on deployment configuration, never on a client claim. */
    private ResponseEntity<LoginStateResponse> offerPasskeyBeforePin(String sessionId, LoginSession session) {
        if (!authFactorPolicy.passkeysSupported()) {
            return advanceToPinSetup(sessionId, session);
        }
        session.setPhase(Phase.PASSKEY_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    private ResponseEntity<LoginStateResponse> advanceToPinSetup(String sessionId, LoginSession session) {
        session.setPhase(Phase.PIN_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    private ResponseEntity<LoginStateResponse> advanceToPasskeySetup(String sessionId, LoginSession session) {
        if (!authFactorPolicy.passkeysSupported() || authFactorPolicy.passkeyHeld(session.getUserId())) {
            return complete(sessionId, session);
        }
        session.setPhase(Phase.PASSKEY_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /** Deliberately generic so it does not reveal whether the phone exists. */
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

    /** PROFILE_REQUIRED must stay excluded: an assertion accepted there would reach account creation. */
    private void requireAssertionPhase(LoginSession session) {
        requirePhase(session, Phase.PHONE, Phase.OTP_SENT, Phase.PIN_REQUIRED, Phase.PASSKEY_REQUIRED);
    }

    /** An enrollment session carries no OIDC request and must never reach complete(). */
    private void refuseEnrollmentSignIn(LoginSession session) {
        if (session.isEnroll()) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "enroll_session_cannot_sign_in",
                    "This session is for adding a passkey, not for signing in.");
        }
    }

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

    /** The SMS proof is only for an account that holds no factor. */
    private void requireNoStrongerFactor(LoginSession session) {
        if (!authFactorPolicy.loginPolicy(session.getUserId()).factorSetupRequired()) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "step_up_factor_available",
                    "Confirm with the passkey or PIN on this account.");
        }
    }

    // Sets enrollStepUpFactor, never authenticatedFactor: an enrollment session must not be able to finish a
    // sign-in.
    private ResponseEntity<LoginStateResponse> acceptEnrollStepUp(String sessionId, LoginSession session,
            AuthFactor provedWith) {
        session.setEnrollStepUpFactor(provedWith);
        session.setPhase(session.getEnrollTarget() == LoginSession.EnrollTarget.PIN
                ? Phase.PIN_SETUP
                : Phase.PASSKEY_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /** A bearer token alone must never add a durable factor. */
    private void requireEnrollStepUpDone(LoginSession session) {
        if (session.isEnroll() && session.getEnrollStepUpFactor() == null) {
            throw new StepUpRequiredException(
                    "Confirm it is you before adding a way to sign in.");
        }
    }

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

    /** Null unless the phase is in FACTOR_REPORT_PHASES and the session carries the resolved subject. */
    private AuthFactorPolicy.RegisteredFactors publishableFactors(LoginSession session) {
        if (!FACTOR_REPORT_PHASES.contains(session.getPhase()) || !StringUtils.hasText(session.getUserId())) {
            return null;
        }
        return authFactorPolicy.registeredFactors(session.getUserId());
    }

    /** Published at the enrollment step-up only, where the caller can already read it from /security/pin/status. */
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

    public record PhoneRequest(@NotBlank String phoneNumber, String locale) {
    }

    public record OtpRequest(@NotBlank String code) {
    }

    public record PinRequest(@NotBlank String pin) {
    }

    /** skip is still accepted on the wire so an older client gets pin_required. */
    public record PinSetupRequest(String pin, boolean skip) {
    }

    public record RecoveryCompleteRequest(String newPin) {
    }

    /** Base64url Ed25519 signature. Absent when the signup is not attaching a genesis. */
    public record ProfileRequest(@NotBlank String username, String displayName, String attachProof) {
    }

    public record PasskeyCredentialRequest(@NotNull JsonNode credential) {
    }

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
            /** Base64url. Null and omitted unless this session is attaching a genesis. */
            String genesisAttachChallenge,
            /** Null and omitted until the session has proved whose account it is. */
            Boolean passkeyRegistered,
            Boolean pinRegistered,
            String preferredFactor,
            Boolean passkeysEnabled,
            boolean enrollment,
            /** Always present, as an explicit null when recovery is unavailable. */
            @JsonInclude(JsonInclude.Include.ALWAYS) AccountRecoveryState recovery) {
    }
}
