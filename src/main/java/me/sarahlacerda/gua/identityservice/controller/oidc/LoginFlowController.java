package me.sarahlacerda.gua.identityservice.controller.oidc;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

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
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactorPolicy;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

/**
 * Server side of the interactive OIDC login flow. The browser is sent here by
 * {@code GET /oauth2/authorize} (which parks the OIDC request in a Redis-backed
 * {@link LoginSession} and drops an opaque cookie); the {@code gua-idp-web}
 * single-page app then drives these endpoints to walk the user through
 * phone &rarr; OTP &rarr; PIN (returning) or profile (new). On success an
 * authorization code is issued and the UI is handed the redirect URL back to
 * the requesting client (MAS).
 *
 * <p>
 * State-changing calls are protected by a double-submit CSRF token issued in
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

    @GetMapping("/context")
    @Operation(summary = "Fetch the current login state", description = "Returns the current step, the login intent (PHONE or PASSKEY, from the OIDC login_hint), a CSRF token to echo on subsequent calls, and the masked phone when known.")
    public ResponseEntity<LoginStateResponse> context(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId) {
        LoginSession session = requireSession(sessionId);
        return ResponseEntity.ok(state(session, null));
    }

    @GetMapping("/passkey/enroll/{token}")
    @Operation(summary = "Open the in-app passkey enrollment web view", description = "One-time handoff for an already-signed-in user adding a passkey from settings. The enrollment session is created by POST /security/passkey/enroll/start; the cookie set on that API call is not present in this separate web view, so this redeems the one-time token, drops the first-party login cookie, and redirects into the sign-in SPA at the passkey setup step.")
    public ResponseEntity<Void> openPasskeyEnrollment(
            @org.springframework.web.bind.annotation.PathVariable("token") String token) {
        String sessionId = loginSessionService.consumeEnrollToken(token)
                .orElseThrow(() -> new LoginFlowException(HttpStatus.GONE, "enroll_link_expired",
                        "This passkey setup link has expired. Please try again."));
        // Confirm the session is still live before establishing the cookie.
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

        // Normalize to canonical E.164 at the boundary so a number supplied without a
        // country code can never key the OTP / phone digest under a different value and
        // silently mint a duplicate account. Rejects anything that isn't a valid number.
        String phone = phoneNumberNormalizer.toE164(request.phoneNumber());
        // Beta gate (inert unless enabled): a web flow may only trigger an OTP for a
        // number that already has an account or is explicitly allowlisted, so an open
        // deployment cannot be used to burn SMS credits or self-register. Native app
        // flows are exempt. Runs before the SMS is dispatched.
        registrationGuard.assertOtpAllowed(session, phone);
        otpService.sendOtp(phone, servletRequest.getRemoteAddr(), request.locale());

        session.setPhoneNumber(phone);
        session.setLocale(request.locale());
        session.setPhase(Phase.OTP_SENT);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    @PostMapping("/otp")
    @Operation(summary = "Verify the OTP", description = "Verifies the one-time code, then routes to the PIN step (returning user with two-step verification), the profile step (new user), or completes login.")
    public ResponseEntity<LoginStateResponse> submitOtp(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid OtpRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.OTP_SENT);

        otpService.verifyOtp(session.getPhoneNumber(), request.code().trim());

        String digest = phoneNumberHasher.digest(session.getPhoneNumber());
        Optional<DirectoryEntry> existing = directoryService.findByDigest(digest);
        if (existing.isPresent()) {
            return routeExistingUser(sessionId, session, existing.get().getUserId(), existing.get());
        }

        // The peppered phone digest missed. Before treating this as a brand-new
        // signup, fall back to the homeserver's phone (msisdn threepid) binding,
        // which is independent of the directory pepper. A rotated/drifted
        // IDENTITY_DIRECTORY_PEPPER, or env/DB drift, orphans the directory row but
        // NOT this binding, so a genuine returning user is still recognised here and
        // is never minted a second MXID + directory row (the duplicate-account bug).
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

        // Re-authentication is LOGIN-ONLY: a phone that resolves to no existing account
        // must be rejected here. It must never fall through to the new-account /
        // username-creation phase for an already signed-in user re-verifying.
        if (session.getReauthUserId() != null) {
            throw reauthMismatch();
        }

        // Genuine no-match anywhere: brand-new user; choose a username + display name.
        session.setNewUser(true);
        session.setPhase(Phase.PROFILE_REQUIRED);
        issueGenesisAttachChallenge(session);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /**
     * Issues the bytes a client must sign to attach its account genesis, when a session carrying a
     * handle enters the profile step (ADM-008 decision 6).
     *
     * <p>Issued once per profile step: a session that already holds a challenge keeps it, so reloading
     * the UI does not invalidate a proof the client has already computed. The value lives only on the
     * server-side session, is handed to the client to sign, and is never accepted back as a lookup key.
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
     * What the profile step knows about this session's account genesis. The handle and the challenge are
     * read from the server-side session; only the proof comes from the client. Returns {@code null} when
     * the feature is off, which leaves the account-creation path exactly as it was before it existed.
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
     * Routes an authenticated returning user (resolved either from the directory
     * digest or the homeserver phone-binding fallback) to the PIN step or straight
     * to passkey setup. Always marks the session as an existing user and emits the
     * account's stored localpart, which MAS imports as {@code preferred_username} on the
     * first delegated login. The localpart is read from the directory row, never
     * derived from {@code userId} (ADM-001 S6); see {@link AccountLocalpartResolver}.
     *
     * @param entry the account's directory row, or {@code null} when none is stored
     */
    private ResponseEntity<LoginStateResponse> routeExistingUser(
            String sessionId, LoginSession session, String userId, DirectoryEntry entry) {
        // On a re-authentication (login-only) the verified phone must belong to the
        // already-authenticated user. A different owner is rejected: the change-phone
        // flow, where the new number is intentionally not yet the user's, runs through a
        // separate endpoint and never sets reauthUserId, so it is unaffected.
        if (session.getReauthUserId() != null && !session.getReauthUserId().equals(userId)) {
            throw reauthMismatch();
        }
        // Returning users are still NEW to MAS on their first delegated login, which
        // requires a localpart. Resolve it before touching the session, so a refusal
        // leaves nothing saved and no authorization code can follow.
        String preferredUsername = accountLocalparts.forExistingAccount(userId,
                entry != null ? List.of(entry) : List.of());
        session.setUserId(userId);
        session.setDisplayName(entry != null ? entry.getDisplayName() : null);
        session.setPreferredUsername(preferredUsername);
        session.setNewUser(false);
        // One answer for "does this account need the PIN step", shared with the native
        // sign-in path and with the phone-change step-up. A registered passkey neither adds
        // this step nor removes it: skipping it would let a device stand in for knowledge,
        // and demanding it would strand a user whose credential broke.
        if (authFactorPolicy.loginPolicy(userId).pinStepRequired()) {
            session.setPhase(Phase.PIN_REQUIRED);
            loginSessionService.save(sessionId, session);
            return ResponseEntity.ok(state(session, null));
        }
        return advanceToPasskeySetup(sessionId, session);
    }

    /**
     * Re-binds the (current-pepper) phone digest to an existing MXID after the
     * directory row was orphaned. Best-effort: a failure here must not block a
     * returning user from signing in, so it is logged and swallowed.
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
     *
     * <p>This is the one runtime path that creates an account the startup backfill could not have seen:
     * no directory row and no security row, so nothing to scan, until the heal above inserts one. Left
     * alone, that account would surface afterwards holding no id at all and would hold
     * {@code gua_identity_accounts_without_genesis} above zero until the next restart, and that gauge
     * reaching zero and staying there is the first of ADM-008's shadow-mode exit criteria.
     *
     * <p>Best-effort and idempotent, like the heal it follows: an account that already holds a row keeps
     * it, and a failure here must never stop a returning user from signing in. A missed account is not
     * lost either way, since the next backfill run picks it up.
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
        return advanceToPasskeySetup(sessionId, session);
    }

    @PostMapping("/profile")
    @Operation(summary = "Choose username and display name", description = "Finalizes a brand-new account: validates the username, reserves the handle, and completes login.")
    public ResponseEntity<LoginStateResponse> submitProfile(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid ProfileRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PROFILE_REQUIRED);
        // Invite-only gate for web signups (inert unless enabled). Runs before any
        // account is provisioned; only the new-user branch reaches here, so existing
        // users, re-auth, change-phone and passkey paths are never affected.
        registrationGuard.assertAllowedForNewUser(session);

        String localpart = usernamePolicy.normalizeAndValidate(request.username());
        // Username uniqueness is enforced within this deployment's directory (the
        // per-homeserver userExists check below only sees one homeserver). It is not
        // federation-wide: that is a property of the sequenced binding log in ADM-001
        // (L11, L12), which nothing here implements.
        if (directoryService.isUsernameTaken(localpart)) {
            throw new UsernameTakenException("Username already taken");
        }

        // This deployment's router picks the homeserver the new account is created on:
        // a local choice, not the committed placement of ADM-001 L6.
        Homeserver homeserver = homeserverRouter
                .selectForNewAccount(AccountPlacementContext.forPhone(session.getPhoneNumber()));
        if (matrixAdminClient.userExists(matrixProvisioningService.buildUserId(localpart, homeserver))) {
            throw new UsernameTakenException("Username already taken");
        }

        // The Matrix localpart is the chosen handle. Build the stable subject (the
        // OIDC sub / directory userId) from the same localpart so sub, the directory
        // entry, and the preferred_username claim MAS imports all agree.
        String userId = matrixProvisioningService.buildUserId(localpart, homeserver);
        String displayName = StringUtils.hasText(request.displayName()) ? request.displayName().trim() : localpart;
        String digest = phoneNumberHasher.digest(session.getPhoneNumber());
        String maskedPhone = phoneNumberMasker.mask(session.getPhoneNumber());
        try {
            // The directory row, this deployment's routing choice and the account's accountId are
            // written as one transaction. ADM-008 decision 6 puts the attach-proof verification inside
            // the account-creation transaction, so a handle that was presented and fails to attach rolls
            // the whole signup back rather than silently downgrading to a bootstrap id.
            accountCreationService.createAccount(digest, maskedPhone, userId, displayName, homeserver.id(),
                    localpart, genesisAttachment(session, request.attachProof()));
        } catch (DataIntegrityViolationException ex) {
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        // Burned only by a successful attach: a failed proof leaves the challenge in place so the client
        // can retry inside this session, and it dies with the session either way.
        session.setGenesisAttachHandle(null);
        session.setGenesisAttachChallenge(null);
        session.setUserId(userId);
        session.setDisplayName(displayName);
        session.setPreferredUsername(localpart);
        // New accounts are offered two-step verification (PIN) before finishing.
        session.setNewUser(true);
        session.setPhase(Phase.PIN_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    @PostMapping("/pin-setup")
    @Operation(summary = "Set up (or skip) an account PIN", description = "Optional two-step verification step offered to brand-new accounts. Sends a PIN to enable it, or skip:true to continue without one.")
    public ResponseEntity<LoginStateResponse> submitPinSetup(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PinSetupRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PIN_SETUP);

        if (!request.skip() && StringUtils.hasText(request.pin())) {
            userSecurityService.setInitialPin(session.getUserId(), request.pin().trim());
        }
        return advanceToPasskeySetup(sessionId, session);
    }

    @PostMapping("/passkey/register/options")
    @Operation(summary = "Start passkey setup", description = "Creates WebAuthn registration options after phone verification and any PIN step are complete.")
    public ResponseEntity<PasskeyOptionsResponse> startPasskeyRegistration(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PASSKEY_SETUP);

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

        passkeyService.finishRegistration(sessionId, session, request.credential());
        return session.isEnroll() ? completeEnrollment(sessionId, session) : complete(sessionId, session);
    }

    @PostMapping("/passkey/setup-skip")
    @Operation(summary = "Skip passkey setup", description = "Completes login without associating a passkey.")
    public ResponseEntity<LoginStateResponse> skipPasskeySetup(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PASSKEY_SETUP);

        return session.isEnroll() ? completeEnrollment(sessionId, session) : complete(sessionId, session);
    }

    @PostMapping("/passkey/auth/options")
    @Operation(summary = "Start passkey sign-in", description = "Begins a passkey assertion from the phone step, letting a returning user with a registered passkey sign in without an OTP. Only ever resolves to a pre-existing account.")
    public ResponseEntity<PasskeyOptionsResponse> startPasskeyAuthentication(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        // Offered at the very start of the flow ("sign in with a passkey"), before OTP.
        requirePhase(session, Phase.PHONE, Phase.OTP_SENT);

        return ResponseEntity.ok(new PasskeyOptionsResponse(passkeyService.startAuthentication(sessionId)));
    }

    @PostMapping("/passkey/auth/verify")
    @Operation(summary = "Finish passkey sign-in", description = "Verifies the WebAuthn assertion and, only when it resolves to an existing OTP-registered account with a phone on file, completes login — intentionally bypassing the OTP step. Never creates an account.")
    public ResponseEntity<LoginStateResponse> finishPasskeyAuthentication(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId,
            @RequestHeader(value = CSRF_HEADER, required = false) String csrf,
            @RequestBody @Valid PasskeyCredentialRequest request) {
        LoginSession session = requireSession(sessionId);
        requireCsrf(session, csrf);
        requirePhase(session, Phase.PHONE, Phase.OTP_SENT);

        PasskeyService.PasskeyAuthentication auth = passkeyService.finishAuthentication(sessionId, request.credential());
        String userId = auth.userId();

        // POLICY: passkey sign-in may bypass OTP, but ONLY for an existing account that
        // already registered via OTP and has a phone on file. The asserted credential must
        // resolve to such an account; otherwise reject. This path must NEVER create an
        // account, set newUser, or reach PROFILE_REQUIRED. The directory row is phone-keyed
        // (phone_digest is its non-null key), so its presence is proof of OTP registration
        // with a phone bound.
        DirectoryEntry entry = directoryService.findByUserId(userId).stream()
                .filter(e -> StringUtils.hasText(e.getPhoneDigest()))
                .findFirst()
                .orElseThrow(() -> new LoginFlowException(HttpStatus.FORBIDDEN, "passkey_user_not_registered",
                        "This passkey is not linked to a registered account."));

        // On a re-authentication the asserted credential must belong to the existing subject.
        if (session.getReauthUserId() != null && !session.getReauthUserId().equals(userId)) {
            throw reauthMismatch();
        }

        // Returning users are still new to MAS on their first delegated login, which needs a
        // localpart (MAS imports it as preferred_username): the directory's stored handle, or
        // the strict MXID fallback when none is stored (AccountLocalpartResolver).
        String preferredUsername = accountLocalparts.forExistingAccount(userId, List.of(entry));
        session.setUserId(userId);
        session.setDisplayName(entry.getDisplayName());
        session.setPreferredUsername(preferredUsername);
        session.setNewUser(false);
        // Intentional OTP bypass: a proven existing user signs in straight through.
        return complete(sessionId, session);
    }

    /**
     * Issues the authorization code for the now-authenticated session, consumes the
     * login session, clears its cookie, and hands the UI the redirect URL back to
     * the requesting client.
     */
    private ResponseEntity<LoginStateResponse> complete(String sessionId, LoginSession session) {
        userSecurityService.recordSuccessfulLogin(session.getUserId());

        OidcAuthorization authorization = new OidcAuthorization(
                session.getUserId(),
                session.getPhoneNumber(),
                session.getDisplayName(),
                session.getPreferredUsername(),
                new LinkedHashSet<>(session.getScope()),
                session.getClientId(),
                session.getNonce());
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
     * Terminal step for the in-app passkey enrollment handoff (an already-signed-in user
     * adding a passkey from settings, entered via {@code POST /security/passkey/enroll/start}).
     * Unlike {@link #complete}, there is no OIDC authorization in flight: the session carries
     * no {@code clientId} / scope / PKCE and nothing is exchanged for a token, so this issues
     * NO authorization code (attempting to would throw on the null client id). It finalizes the
     * session, clears the cookie, and hands the web view the app-scheme redirect it was opened
     * against, so the client's {@code ASWebAuthenticationSession} closes and returns to the app.
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

        // No code/state query params: an app-scheme redirect carrying no OIDC `error` is the
        // client's success signal for enrollment (see PasskeyEnrollmentPresenter on iOS).
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, expired.toString())
                .body(state(session, session.getRedirectUri()));
    }

    private ResponseEntity<LoginStateResponse> advanceToPasskeySetup(String sessionId, LoginSession session) {
        // Don't re-offer passkey setup to an account that already has one: re-registering the same
        // device only fails. Such a user is done authenticating; complete the login straight through.
        // The "already has one" question is AuthFactorPolicy's, so this and the settings entry
        // point at POST /security/passkey/enroll/start cannot answer it differently.
        if (authFactorPolicy.passkeyRegistered(session.getUserId())) {
            return complete(sessionId, session);
        }
        session.setPhase(Phase.PASSKEY_SETUP);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
    }

    /**
     * Single rejection for a re-authentication that fails the login-only contract:
     * the verified phone is unregistered, or registered to a different user than the
     * one re-authenticating. The message is intentionally generic so it does not leak
     * whether the phone exists.
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
        return new LoginStateResponse(
                session.getPhase().name(),
                session.getIntent().name(),
                session.getClientId(),
                maskPhone(session.getPhoneNumber()),
                session.getPhoneHint(),
                session.getCsrfToken(),
                session.isNewUser(),
                redirectUrl,
                session.getGenesisAttachChallenge());
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
     * PIN setup is optional: provide {@code pin} to enable it, or {@code skip:true}
     * to finish without one.
     */
    public record PinSetupRequest(String pin, boolean skip) {
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

    public record PasskeyOptionsResponse(JsonNode publicKey) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LoginStateResponse(
            String phase,
            /** {@code PHONE} or {@code PASSKEY}; clients that predate the field treat it as {@code PHONE}. */
            String intent,
            String clientId,
            String maskedPhone,
            String phoneHint,
            String csrfToken,
            boolean newUser,
            String redirectUrl,
            /**
             * The 32 server-chosen bytes, base64url, this session's client must sign to attach its
             * account genesis. Null, and omitted from the JSON, for every session that is not attaching
             * one, so a client that knows nothing about genesis sees exactly the response it saw before.
             */
            String genesisAttachChallenge) {
    }
}
