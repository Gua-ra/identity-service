package me.sarahlacerda.gua.identityservice.controller.oidc;

import java.util.LinkedHashSet;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;

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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.UsernameTakenException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.MatrixProvisioningService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.UsernamePolicy;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.Phase;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
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
 * <p>State-changing calls are protected by a double-submit CSRF token issued in
 * {@code GET /login/context} and a {@code SameSite=Lax} session cookie.
 */
@RestController
@RequestMapping("/login")
@Validated
@RequiredArgsConstructor
@Tag(name = "Interactive Login", description = "Browser-driven OIDC login flow (phone, OTP, PIN/profile) used by gua-idp-web")
public class LoginFlowController {

    private static final String CSRF_HEADER = "X-CSRF-Token";
    private static final String COOKIE_NAME_EXPR = "${idp.login.cookie-name:gua_login}";

    private final LoginSessionService loginSessionService;
    private final LoginFlowProperties properties;
    private final OtpService otpService;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final UserSecurityService userSecurityService;
    private final MatrixProvisioningService matrixProvisioningService;
    private final MatrixAdminClient matrixAdminClient;
    private final UsernamePolicy usernamePolicy;
    private final OidcAuthorizationService authorizationService;

    @GetMapping("/context")
    @Operation(summary = "Fetch the current login state", description = "Returns the current step, a CSRF token to echo on subsequent calls, and the masked phone when known.")
    public ResponseEntity<LoginStateResponse> context(
            @CookieValue(value = COOKIE_NAME_EXPR, required = false) String sessionId) {
        LoginSession session = requireSession(sessionId);
        return ResponseEntity.ok(state(session, null));
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

        String phone = request.phoneNumber().trim();
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
            DirectoryEntry entry = existing.get();
            session.setUserId(entry.getUserId());
            session.setDisplayName(entry.getDisplayName());
            session.setNewUser(false);
            if (userSecurityService.hasPin(entry.getUserId())) {
                session.setPhase(Phase.PIN_REQUIRED);
                loginSessionService.save(sessionId, session);
                return ResponseEntity.ok(state(session, null));
            }
            return complete(sessionId, session);
        }

        // Brand-new user: choose a username + display name next.
        session.setNewUser(true);
        session.setPhase(Phase.PROFILE_REQUIRED);
        loginSessionService.save(sessionId, session);
        return ResponseEntity.ok(state(session, null));
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
        return complete(sessionId, session);
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

        String localpart = usernamePolicy.normalizeAndValidate(request.username());
        if (matrixAdminClient.userExists(matrixProvisioningService.buildUserId(localpart))) {
            throw new UsernameTakenException("Username already taken");
        }

        // The OIDC subject is an opaque, stable id; the chosen handle travels as the
        // preferred_username claim so MAS uses it as the Matrix localpart on first
        // provisioning. After that, MAS keys off the immutable sub.
        String userId = matrixProvisioningService.generateOpaqueUserId();
        String displayName = StringUtils.hasText(request.displayName()) ? request.displayName().trim() : localpart;
        String digest = phoneNumberHasher.digest(session.getPhoneNumber());
        try {
            directoryService.upsertByDigest(digest, userId, displayName);
        } catch (DataIntegrityViolationException ex) {
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        session.setUserId(userId);
        session.setDisplayName(displayName);
        session.setPreferredUsername(localpart);
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
                session.getClientId(),
                maskPhone(session.getPhoneNumber()),
                session.getPhoneHint(),
                session.getCsrfToken(),
                session.isNewUser(),
                redirectUrl);
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

    public record PhoneRequest(@NotBlank String phoneNumber, String locale) {}

    public record OtpRequest(@NotBlank String code) {}

    public record PinRequest(@NotBlank String pin) {}

    public record ProfileRequest(@NotBlank String username, String displayName) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LoginStateResponse(
            String phase,
            String clientId,
            String maskedPhone,
            String phoneHint,
            String csrfToken,
            boolean newUser,
            String redirectUrl) {}
}
