package me.sarahlacerda.gua.identityservice.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.controller.oidc.LoginFlowController;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
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
import me.sarahlacerda.gua.identityservice.service.UsernamePolicy;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRouter;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.Phase;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.SessionFactor;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryCooldownException;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryNotReadyException;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryService;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState;
import me.sarahlacerda.gua.identityservice.service.security.LoginFactorEnrollmentService;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(LoginFlowController.class)
@AutoConfigureMockMvc(addFilters = false)
@AutoConfigureObservability   // provide a MeterRegistry in the slice (micrometer-prometheus is on the classpath)
@org.springframework.context.annotation.Import(LoginFlowControllerTest.GuardConfig.class)
class LoginFlowControllerTest {

    // Sign-in does not weigh how old the asserted credential is; only the phone-change
    // step-up does. An established credential keeps that out of the way of these tests.
    private static final Instant REGISTERED_LONG_AGO = Instant.now().minus(Duration.ofDays(400));

    // Use the real RegistrationGuard so the gate behaviour is exercised end-to-end;
    // it is driven through the mocked LoginFlowProperties / PhoneNumberNormalizer /
    // DirectoryService / PhoneNumberHasher / MatrixAdminClient beans in the slice.
    @org.springframework.boot.test.context.TestConfiguration
    static class GuardConfig {
        @org.springframework.context.annotation.Bean
        RegistrationGuard registrationGuard(LoginFlowProperties properties, PhoneNumberNormalizer normalizer,
                DirectoryService directoryService, PhoneNumberHasher phoneNumberHasher,
                MatrixAdminClient matrixAdminClient) {
            return new RegistrationGuard(properties, normalizer, directoryService, phoneNumberHasher,
                    matrixAdminClient);
        }

        // The real resolver, so the localpart each returning path emits is exercised end to end.
        @org.springframework.context.annotation.Bean
        AccountLocalpartResolver accountLocalpartResolver(DirectoryService directoryService) {
            return new AccountLocalpartResolver(directoryService);
        }

        // The real factor policy over the mocked UserSecurityService / PasskeyService, so the
        // PIN step and the "already has a passkey" question are decided by the component the
        // application uses. The existing hasPin / hasPasskey stubs below drive it unchanged.
        @org.springframework.context.annotation.Bean
        me.sarahlacerda.gua.identityservice.service.security.AuthFactorPolicy authFactorPolicy(
                UserSecurityService userSecurityService, PasskeyService passkeyService) {
            return new me.sarahlacerda.gua.identityservice.service.security.AuthFactorPolicy(
                    userSecurityService, passkeyService);
        }

        // The real account-creation service, so the directory writes these tests assert on are the ones
        // the signup path actually performs. Account genesis is mocked and off, so it contributes
        // nothing here: that is the "flag off changes nothing" case, exercised by every test below.
        @org.springframework.context.annotation.Bean
        AccountCreationService accountCreationService(DirectoryService directoryService,
                AccountGenesisService accountGenesisService) {
            return new AccountCreationService(directoryService, accountGenesisService);
        }
    }

    private static final String SID = "session-id";
    private static final String CSRF = "csrf-token";
    private static final String CALLBACK = "https://mas.example.com/callback";
    private static final String ENROLL_APP_SCHEME = "global.gua:/oidc";
    private static final String PHONE = "+15551234567";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private LoginSessionService loginSessionService;
    @MockitoBean
    private LoginFlowProperties properties;
    @MockitoBean
    private OtpService otpService;
    @MockitoBean
    private DirectoryService directoryService;
    @MockitoBean
    private PhoneNumberHasher phoneNumberHasher;
    @MockitoBean
    private PhoneNumberMasker phoneNumberMasker;
    @MockitoBean
    private PhoneNumberNormalizer phoneNumberNormalizer;
    @MockitoBean
    private UserSecurityService userSecurityService;
    @MockitoBean
    private MatrixProvisioningService matrixProvisioningService;
    @MockitoBean
    private MatrixAdminClient matrixAdminClient;
    @MockitoBean
    private UsernamePolicy usernamePolicy;
    @MockitoBean
    private OidcAuthorizationService authorizationService;
    @MockitoBean
    private PasskeyService passkeyService;
    @MockitoBean
    private HomeserverRouter homeserverRouter;
    @MockitoBean
    private EndpointRateLimiter endpointRateLimiter;
    @MockitoBean
    private AccountGenesisService accountGenesisService;
    @MockitoBean
    private LoginFactorEnrollmentService loginFactorEnrollmentService;
    @MockitoBean
    private AccountRecoveryService accountRecoveryService;
    @MockitoBean
    private TokenRevocationService tokenRevocationService;

    @BeforeEach
    void setUp() {
        when(properties.getCookieName()).thenReturn("gua_login");
        // Default: registration allowlist disabled, so the guard is a no-op (open).
        when(properties.getRegistration()).thenReturn(new LoginFlowProperties.Registration());
        when(phoneNumberNormalizer.toE164(PHONE)).thenReturn(PHONE);
        when(homeserverRouter.selectForNewAccount(any()))
                .thenReturn(new me.sarahlacerda.gua.identityservice.domain.Homeserver(
                        "default", "dev.local", null, null, null, null, 1, true));
    }

    private LoginSession session(Phase phase) {
        LoginSession session = new LoginSession();
        session.setClientId("mas");
        session.setRedirectUri(CALLBACK);
        session.setScope(List.of("openid", "profile"));
        session.setState("xyz");
        session.setNonce("nonce-1");
        session.setCsrfToken(CSRF);
        session.setPhase(phase);
        session.setPhoneNumber(PHONE);
        return session;
    }

    private Cookie cookie() {
        return new Cookie("gua_login", SID);
    }

    private OidcAuthorizationCode issuedCode() {
        return new OidcAuthorizationCode("auth-code",
                new OidcAuthorization("u1", PHONE, "Alice", Set.of("openid"), "mas"), CALLBACK);
    }

    @Test
    void contextReturns410WhenSessionMissing() throws Exception {
        when(loginSessionService.find(any())).thenReturn(Optional.empty());

        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value("login_session_expired"));
    }

    @Test
    void contextExposesPhoneIntentByDefault() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));

        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PHONE"))
                .andExpect(jsonPath("$.intent").value("PHONE"))
                .andExpect(jsonPath("$.csrfToken").value(CSRF));
    }

    @Test
    void contextExposesPasskeyIntent() throws Exception {
        LoginSession session = session(Phase.PHONE);
        session.setIntent(LoginSession.Intent.PASSKEY);
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PHONE"))
                .andExpect(jsonPath("$.intent").value("PASSKEY"));
    }

    @Test
    void openPasskeyEnrollmentSetsCookieAndRedirectsToSignin() throws Exception {
        when(properties.getCookieName()).thenReturn("gua_login");
        when(properties.isCookieSecure()).thenReturn(true);
        when(properties.getSessionTtl()).thenReturn(java.time.Duration.ofMinutes(10));
        when(properties.getUiUrl()).thenReturn("/signin");
        when(loginSessionService.consumeEnrollToken("tok-1")).thenReturn(Optional.of(SID));
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PASSKEY_SETUP)));

        mockMvc.perform(get("/login/passkey/enroll/{token}", "tok-1"))
                .andExpect(status().isFound())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                        .string("Location", "/signin"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                        .string("Set-Cookie", org.hamcrest.Matchers.allOf(
                                org.hamcrest.Matchers.containsString("gua_login=" + SID),
                                org.hamcrest.Matchers.containsString("HttpOnly"),
                                org.hamcrest.Matchers.containsString("Secure"),
                                org.hamcrest.Matchers.containsString("SameSite=Lax"))));
    }

    @Test
    void openPasskeyEnrollmentRejectsExpiredToken() throws Exception {
        when(loginSessionService.consumeEnrollToken("tok-1")).thenReturn(Optional.empty());

        mockMvc.perform(get("/login/passkey/enroll/{token}", "tok-1"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value("enroll_link_expired"));
    }

    @Test
    void submitPhoneDispatchesOtpAndAdvances() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));

        mockMvc.perform(post("/login/phone")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"phoneNumber\":\"" + PHONE + "\",\"locale\":\"pt-BR\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("OTP_SENT"))
                .andExpect(jsonPath("$.maskedPhone").value("\u2022\u2022\u2022\u20224567"));

        verify(otpService).sendOtp(eq(PHONE), anyString(), eq("pt-BR"));
    }

    @Test
    void submitPhoneRejectsUnnormalizablePhoneNumber() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));
        when(phoneNumberNormalizer.toE164("555-1234"))
                .thenThrow(new me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException(
                        "Phone number is not valid"));

        mockMvc.perform(post("/login/phone")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"phoneNumber\":\"555-1234\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_phone_number"));

        verify(otpService, org.mockito.Mockito.never()).sendOtp(any(), any(), any());
    }

    @Test
    void submitPhoneNormalizesToE164BeforeKeyingOtp() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));
        when(phoneNumberNormalizer.toE164("5551234567")).thenReturn(PHONE);

        mockMvc.perform(post("/login/phone")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"phoneNumber\":\"5551234567\",\"locale\":\"en-CA\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("OTP_SENT"));

        // OTP is keyed by the normalized E.164 value, not the raw national input.
        verify(otpService).sendOtp(eq(PHONE), anyString(), eq("en-CA"));
    }

    @Test
    void reauthRoutesToExistingUserWhenPhoneBelongsToReauthSubject() throws Exception {
        LoginSession session = session(Phase.OTP_SENT);
        session.setReauthUserId("u1");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").username("alice")
                .displayName("Alice").build();
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));
        when(userSecurityService.hasPin("u1")).thenReturn(true);

        // A re-authentication goes through the same factor gate as any other sign-in.
        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_REQUIRED"))
                .andExpect(jsonPath("$.redirectUrl").doesNotExist())
                // Recovery is never offered to a re-authentication.
                .andExpect(jsonPath("$.recovery").doesNotExist());

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void reauthRejectsPhoneBelongingToDifferentUser() throws Exception {
        LoginSession session = session(Phase.OTP_SENT);
        session.setReauthUserId("u1");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u2").displayName("Bob").build();
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("reauth_user_mismatch"));
    }

    @Test
    void reauthRejectsUnregisteredPhoneInsteadOfStartingSignup() throws Exception {
        LoginSession session = session(Phase.OTP_SENT);
        session.setReauthUserId("u1");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.empty());

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("reauth_user_mismatch"));
    }

    /**
     * D1/D2 for an older account that holds no factor: the OTP proves the number and nothing
     * more, so the account is offered the passkey and never completed.
     */
    @Test
    void submitOtpForAReturningAccountHoldingNoFactorOffersThePasskeyInsteadOfCompleting() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").username("alice")
                .displayName("Alice").build();
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));
        when(userSecurityService.hasPin("u1")).thenReturn(false);
        when(passkeyService.isEnabled()).thenReturn(true);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"))
                .andExpect(jsonPath("$.redirectUrl").doesNotExist());

        verify(otpService).verifyOtp(PHONE, "123456");
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void aReturningAccountHoldingNoFactorLandsOnPinSetupWhenTheDeploymentHasNoPasskeys() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").username("alice")
                .displayName("Alice").build();
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));
        when(passkeyService.isEnabled()).thenReturn(false);

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void submitOtpForReturningUserWithPinRoutesToPin() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").username("alice")
                .displayName("Alice").build();
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));
        when(userSecurityService.hasPin("u1")).thenReturn(true);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_REQUIRED"));
    }

    @Test
    void submitOtpForNewUserRoutesToProfile() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        // No homeserver phone binding either: genuine no-match -> signup.
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.empty());

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PROFILE_REQUIRED"))
                .andExpect(jsonPath("$.newUser").value(true));
    }

    @Test
    void submitOtpRecoversExistingUserViaHomeserverBindingWhenDigestMisses() throws Exception {
        // Directory digest misses (e.g. rotated/drifted pepper) but the phone is
        // still bound to an existing MXID on the homeserver. The user must be routed
        // as an EXISTING user (no signup, no duplicate account) and the directory row
        // must be healed.
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.of("@alice:dev.local"));
        when(phoneNumberMasker.mask(PHONE)).thenReturn("••••4567");
        when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(false);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                // Holds no factor, and this deployment has no passkeys: the mandatory PIN step.
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"))
                .andExpect(jsonPath("$.newUser").value(false));

        // Heals the directory row under the current pepper's digest, reusing the MXID.
        verify(directoryService).upsertByDigest(eq("digest"), any(), eq("@alice:dev.local"),
                org.mockito.ArgumentMatchers.isNull());
    }

    @Test
    void submitOtpRecoveredUserWithPinRoutesToPin() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.of("@alice:dev.local"));
        when(phoneNumberMasker.mask(PHONE)).thenReturn("••••4567");
        when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(true);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_REQUIRED"))
                .andExpect(jsonPath("$.newUser").value(false));
    }

    @Test
    void submitPinRoutesToPasskeySetupForReturningUser() throws Exception {
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("u1");
        session.setDisplayName("Alice");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/pin")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"pin\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"));

        verify(userSecurityService).validatePinOrThrow("u1", "123456");
        assertEquals(SessionFactor.PIN, session.getAuthenticatedFactor());
    }

    @Test
    void submitProfileReservesUsernameAndAdvancesToPinSetup() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PROFILE_REQUIRED)));
        when(usernamePolicy.normalizeAndValidate("Alice")).thenReturn("alice");
        when(directoryService.isUsernameTaken("alice")).thenReturn(false);
        when(matrixProvisioningService.buildUserId(eq("alice"), any())).thenReturn("@alice:gua.local");
        when(matrixAdminClient.userExists("@alice:gua.local")).thenReturn(false);

        mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"Alice\",\"displayName\":\"Alice A\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(directoryService).upsertByDigest(any(), any(), eq("@alice:gua.local"), eq("Alice A"));
    }

    /**
     * The PIN step is now the tail of signup rather than its middle: the passkey was offered
     * before it, so nothing follows it. Routing back to the passkey offer here would be a loop,
     * since declining that offer is the only way into this step.
     */
    @Test
    void submitPinSetupWithPinSetsItAndCompletesLogin() throws Exception {
        LoginSession session = session(Phase.PIN_SETUP);
        session.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/pin-setup")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"pin\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.redirectUrl").value(CALLBACK + "?code=auth-code&state=xyz"));

        verify(loginFactorEnrollmentService).setUpFirstPin("@alice:gua.local", "123456");
        assertEquals(SessionFactor.ENROLLED, session.getAuthenticatedFactor());
        // Not a recovery, so the tokens never ask for other sessions to end.
        assertEquals(false, issuedAuthorization().endOtherSessions());
    }

    /** D2: the PIN step is where a factorless account gets its factor, so it cannot be left without one. */
    @Test
    void pinSetupCannotBeSkippedOrLeftBlankAndNeverCompletes() throws Exception {
        LoginSession session = session(Phase.PIN_SETUP);
        session.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        for (String body : new String[] { "{\"skip\":true}", "{}", "{\"pin\":\"   \"}", "{\"pin\":\"\"}",
                "{\"pin\":\"284917\",\"skip\":true}" }) {
            mockMvc.perform(post("/login/pin-setup")
                    .cookie(cookie())
                    .header("X-CSRF-Token", CSRF)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("pin_required"));
        }

        verify(loginFactorEnrollmentService, org.mockito.Mockito.never()).setUpFirstPin(any(), any());
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
        verify(userSecurityService, org.mockito.Mockito.never()).recordSuccessfulLogin(any());
    }

    @Test
    void passkeyRegistrationOptionsAreAvailableAfterPinStep() throws Exception {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
        ObjectNode options = JsonNodeFactory.instance.objectNode();
        options.put("challenge", "abc");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(passkeyService.startRegistration(SID, session)).thenReturn(options);

        mockMvc.perform(post("/login/passkey/register/options")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey.challenge").value("abc"));
    }

    @Test
    void passkeyRegistrationVerifyCompletesLogin() throws Exception {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(loginFactorEnrollmentService.registerPasskey(eq(SID), eq(session), any())).thenReturn(true);
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/passkey/register/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.redirectUrl").value(CALLBACK + "?code=auth-code&state=xyz"));

        verify(loginFactorEnrollmentService).registerPasskey(eq(SID), eq(session), any());
        assertEquals(SessionFactor.ENROLLED, session.getAuthenticatedFactor());
    }

    /** Declining the extra passkey offered after a PIN sign-in finishes the sign-in the PIN earned. */
    @Test
    void passkeySetupSkipCompletesASessionThatSignedInWithItsPin() throws Exception {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
        session.setAuthenticatedFactor(SessionFactor.PIN);
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/passkey/setup-skip")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.redirectUrl").value(CALLBACK + "?code=auth-code&state=xyz"));
    }

    /**
     * An in-app passkey enrollment (already-signed-in user adding a passkey from settings) has
     * no OIDC authorization in flight, so its session carries no client id. Completing it must
     * redirect the web view back to the app scheme WITHOUT issuing an authorization code —
     * previously this ran the login completion and threw {@code clientId must not be null}.
     */
    @Test
    void passkeyEnrollmentVerifyRedirectsToAppSchemeAndIssuesNoCode() throws Exception {
        LoginSession session = enrollSession();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/passkey/register/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.redirectUrl").value(ENROLL_APP_SCHEME));

        verify(passkeyService).finishRegistration(eq(SID), eq(session), any());
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void passkeyEnrollmentSkipRedirectsToAppSchemeAndIssuesNoCode() throws Exception {
        LoginSession session = enrollSession();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/passkey/setup-skip")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.redirectUrl").value(ENROLL_APP_SCHEME));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    /** Mirrors SecurityController.startPasskeyEnrollment: an enrollment session has no OIDC client. */
    private LoginSession enrollSession() {
        LoginSession session = new LoginSession();
        session.setEnroll(true);
        session.setUserId("@alice:gua.local");
        session.setReauthUserId("@alice:gua.local");
        session.setRedirectUri(ENROLL_APP_SCHEME);
        session.setCsrfToken(CSRF);
        session.setPhase(Phase.PASSKEY_SETUP);
        return session;
    }

    @Test
    void passkeyAuthOptionsAreOfferedBeforeOtp() throws Exception {
        ObjectNode options = JsonNodeFactory.instance.objectNode();
        options.put("challenge", "abc");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));
        when(passkeyService.startAuthentication(SID)).thenReturn(options);

        mockMvc.perform(post("/login/passkey/auth/options")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey.challenge").value("abc"));
    }

    /**
     * The intent is UI guidance only. A session flagged PASSKEY that has already
     * moved to the OTP step still gets assertion options, exactly like a phone-intent
     * session at either step.
     */
    @Test
    void passkeyAuthOptionsIgnoreIntentAndStayAvailableAtOtpStep() throws Exception {
        ObjectNode options = JsonNodeFactory.instance.objectNode();
        options.put("challenge", "abc");
        LoginSession session = session(Phase.OTP_SENT);
        session.setIntent(LoginSession.Intent.PASSKEY);
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(passkeyService.startAuthentication(SID)).thenReturn(options);

        mockMvc.perform(post("/login/passkey/auth/options")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey.challenge").value("abc"));
    }

    @Test
    void passkeyAuthVerifyForRegisteredUserSkipsOtpAndCompletes() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@alice:dev.local", REGISTERED_LONG_AGO));
        DirectoryEntry entry = DirectoryEntry.builder()
                .phoneDigest("digest").userId("@alice:dev.local").username("alice").displayName("Alice").build();
        when(directoryService.findByUserId("@alice:dev.local")).thenReturn(List.of(entry));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.newUser").value(false))
                .andExpect(jsonPath("$.redirectUrl").value(CALLBACK + "?code=auth-code&state=xyz"));

        // OTP is bypassed entirely for a proven existing user.
        verify(otpService, org.mockito.Mockito.never()).verifyOtp(any(), any());
        // The stored username is what MAS is told.
        assertEquals("alice", issuedAuthorization().preferredUsername());
    }

    @Test
    void passkeyAuthVerifyRejectsUserNotRegisteredAndCreatesNoAccount() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@ghost:dev.local", REGISTERED_LONG_AGO));
        // The asserted credential resolves to no directory row (no OTP registration / no phone).
        when(directoryService.findByUserId("@ghost:dev.local")).thenReturn(List.of());

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("passkey_user_not_registered"));

        // Never mints an account or issues a code for an unregistered subject.
        verify(directoryService, org.mockito.Mockito.never()).upsertByDigest(any(), any(), any(), any());
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void passkeyAuthVerifyRejectsWhenResolvedUserMismatchesReauthSubject() throws Exception {
        LoginSession session = session(Phase.PHONE);
        session.setReauthUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@bob:dev.local", REGISTERED_LONG_AGO));
        DirectoryEntry entry = DirectoryEntry.builder()
                .phoneDigest("digest").userId("@bob:dev.local").username("bob").displayName("Bob").build();
        when(directoryService.findByUserId("@bob:dev.local")).thenReturn(List.of(entry));

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("reauth_user_mismatch"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void passkeyAuthVerifyWithoutStoredUsernameFallsBackToTheMxidLocalpart() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@alice:dev.local", REGISTERED_LONG_AGO));
        when(directoryService.findByUserId("@alice:dev.local")).thenReturn(List.of(
                DirectoryEntry.builder().phoneDigest("digest").userId("@alice:dev.local").displayName("Alice").build()));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"));

        assertEquals("alice", issuedAuthorization().preferredUsername());
    }

    @Test
    void passkeyAuthVerifyRefusesNonMatrixUserIdWithoutStoredUsernameAndIssuesNoCode() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("ga1abc:x", REGISTERED_LONG_AGO));
        when(directoryService.findByUserId("ga1abc:x")).thenReturn(List.of(
                DirectoryEntry.builder().phoneDigest("digest").userId("ga1abc:x").displayName("Alice").build()));

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value("account_identity_inconsistent"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    // --- Existing-account localpart (ADM-001 S6) --------------------------

    /**
     * The account holds only a passkey, so the OTP routes it to PASSKEY_REQUIRED and the session
     * saved there carries the localpart its completion will hand to MAS.
     */
    private void stubAccountAlreadyHasPasskey(String userId) {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(userId)).thenReturn(true);
    }

    /** The localpart the routed session will emit as preferred_username when it completes. */
    private String routedPreferredUsername() {
        org.mockito.ArgumentCaptor<LoginSession> saved = org.mockito.ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).save(eq(SID), saved.capture());
        return saved.getValue().getPreferredUsername();
    }

    /** The authorization the issued code carries, which is what the tokens will say. */
    private OidcAuthorization issuedAuthorization() {
        org.mockito.ArgumentCaptor<OidcAuthorization> captor =
                org.mockito.ArgumentCaptor.forClass(OidcAuthorization.class);
        verify(authorizationService).issueCode(captor.capture(), eq(CALLBACK), any());
        return captor.getValue();
    }

    private void stubReturningDigest(DirectoryEntry entry) {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));
    }

    private org.springframework.test.web.servlet.ResultActions performOtp() throws Exception {
        return mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"));
    }

    @Test
    void returningUserEmitsTheStoredUsername() throws Exception {
        stubReturningDigest(DirectoryEntry.builder().phoneDigest("digest").userId("@alice:dev.local")
                .username("alice.s").displayName("Alice").build());
        stubAccountAlreadyHasPasskey("@alice:dev.local");

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_REQUIRED"));

        org.mockito.ArgumentCaptor<LoginSession> saved = org.mockito.ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).save(eq(SID), saved.capture());
        // sub stays the MXID; the localpart is the stored username, not the MXID's.
        assertEquals("@alice:dev.local", saved.getValue().getUserId());
        assertEquals("alice.s", saved.getValue().getPreferredUsername());
    }

    /** The S6 trap: a re-keyed, colon-bearing user_id must not change what MAS is told. */
    @Test
    void returningUserWithReKeyedUserIdStillEmitsTheStoredUsername() throws Exception {
        stubReturningDigest(DirectoryEntry.builder().phoneDigest("digest").userId("ga1abc:x")
                .username("alice").displayName("Alice").build());
        stubAccountAlreadyHasPasskey("ga1abc:x");

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_REQUIRED"));

        assertEquals("alice", routedPreferredUsername());
    }

    @Test
    void returningUserWithoutStoredUsernameEmitsTheMxidLocalpart() throws Exception {
        stubReturningDigest(DirectoryEntry.builder().phoneDigest("digest").userId("@alice:dev.local")
                .displayName("Alice").build());
        stubAccountAlreadyHasPasskey("@alice:dev.local");

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_REQUIRED"));

        assertEquals("alice", routedPreferredUsername());
    }

    @Test
    void colonBearingNonMatrixUserIdWithoutStoredUsernameIsRefusedAndIssuesNoCode() throws Exception {
        stubReturningDigest(DirectoryEntry.builder().phoneDigest("digest").userId("ga1abc:x")
                .displayName("Alice").build());

        performOtp()
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value("account_identity_inconsistent"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
        verify(loginSessionService, org.mockito.Mockito.never()).save(any(), any());
        verify(userSecurityService, org.mockito.Mockito.never()).hasPin(any());
    }

    @Test
    void fallbackLocalpartHeldByAnotherAccountIsRefusedAndIssuesNoCode() throws Exception {
        stubReturningDigest(DirectoryEntry.builder().phoneDigest("digest").userId("@alice:dev.local")
                .displayName("Alice").build());
        when(directoryService.resolveByUsername("alice")).thenReturn(Optional.of(DirectoryEntry.builder()
                .phoneDigest("other-digest").userId("@alice:other.local").username("alice").build()));

        performOtp()
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value("account_identity_inconsistent"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void healedRowTakesTheMxidLocalpartFallback() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        // Digest misses, the homeserver binding recovers the account, the heal writes a row
        // with no stored username.
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty(), Optional.of(
                DirectoryEntry.builder().phoneDigest("digest").userId("@alice:dev.local").build()));
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.of("@alice:dev.local"));
        when(phoneNumberMasker.mask(PHONE)).thenReturn("••••4567");
        stubAccountAlreadyHasPasskey("@alice:dev.local");

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_REQUIRED"))
                .andExpect(jsonPath("$.newUser").value(false));

        assertEquals("alice", routedPreferredUsername());
    }

    // --- Web registration allowlist guard ---------------------------------

    /** Registration config with the allowlist enabled for the given E.164 entries. */
    private LoginFlowProperties.Registration enabledAllowlist(String... entries) {
        LoginFlowProperties.Registration registration = new LoginFlowProperties.Registration();
        registration.setWebAllowlistEnabled(true);
        registration.setWebAllowlist(List.of(entries));
        return registration;
    }

    private void stubNewSignupWith(LoginSession session) {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(usernamePolicy.normalizeAndValidate("Alice")).thenReturn("alice");
        when(directoryService.isUsernameTaken("alice")).thenReturn(false);
        when(matrixProvisioningService.buildUserId(eq("alice"), any())).thenReturn("@alice:gua.local");
        when(matrixAdminClient.userExists("@alice:gua.local")).thenReturn(false);
    }

    private org.springframework.test.web.servlet.ResultActions performProfile() throws Exception {
        return mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"Alice\",\"displayName\":\"Alice A\"}"));
    }

    @Test
    void newWebSignupNotAllowlistedIsRejectedAndCreatesNoAccount() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.PROFILE_REQUIRED);
        session.setDownstreamClient("web");
        stubNewSignupWith(session);

        performProfile()
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("registration_not_approved"));

        verify(directoryService, org.mockito.Mockito.never()).upsertByDigest(any(), any(), any(), any());
    }

    @Test
    void newWebSignupAllowlistedIsCreated() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist(PHONE));
        LoginSession session = session(Phase.PROFILE_REQUIRED);
        session.setDownstreamClient("web");
        stubNewSignupWith(session);

        performProfile()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(directoryService).upsertByDigest(any(), any(), eq("@alice:gua.local"), eq("Alice A"));
    }

    @Test
    void newNativeSignupIsCreatedRegardlessOfAllowlist() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.PROFILE_REQUIRED);
        session.setDownstreamClient("native");
        stubNewSignupWith(session);

        performProfile()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(directoryService).upsertByDigest(any(), any(), eq("@alice:gua.local"), eq("Alice A"));
    }

    @Test
    void newSignupWithAbsentDownstreamSignalFailsClosedWhenEnabled() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.PROFILE_REQUIRED);
        // downstreamClient left null: fail closed, treated as a web signup.
        stubNewSignupWith(session);

        performProfile()
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("registration_not_approved"));

        verify(directoryService, org.mockito.Mockito.never()).upsertByDigest(any(), any(), any(), any());
    }

    @Test
    void newSignupWithAbsentDownstreamSignalIsCreatedWhenAllowlisted() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist(PHONE));
        LoginSession session = session(Phase.PROFILE_REQUIRED);
        // downstreamClient null but the phone is allowlisted: created.
        stubNewSignupWith(session);

        performProfile()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(directoryService).upsertByDigest(any(), any(), eq("@alice:gua.local"), eq("Alice A"));
    }

    @Test
    void newSignupWithUnrecognisedDownstreamMarkerIsGatedAsWeb() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.PROFILE_REQUIRED);
        // Only the exact native marker is exempt; any other value counts as web.
        session.setDownstreamClient("Native");
        stubNewSignupWith(session);

        performProfile()
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("registration_not_approved"));

        verify(directoryService, org.mockito.Mockito.never()).upsertByDigest(any(), any(), any(), any());
    }

    @Test
    void newWebSignupIsCreatedWhenAllowlistDisabled() throws Exception {
        // Default registration (disabled) from setUp(): guard is open regardless of phone.
        LoginSession session = session(Phase.PROFILE_REQUIRED);
        session.setDownstreamClient("web");
        stubNewSignupWith(session);

        performProfile()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(directoryService).upsertByDigest(any(), any(), eq("@alice:gua.local"), eq("Alice A"));
    }

    @Test
    void existingWebUserNotAllowlistedStillLogsIn() throws Exception {
        // The guard must never touch an existing user: even with the allowlist on and
        // this user's phone absent from it, a returning web login succeeds because it
        // resolves in submitOtp (routeExistingUser), never reaching the profile branch.
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.OTP_SENT);
        session.setDownstreamClient("web");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").username("alice")
                .displayName("Alice").build();
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));
        when(userSecurityService.hasPin("u1")).thenReturn(true);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_REQUIRED"))
                .andExpect(jsonPath("$.newUser").value(false));
    }

    @Test
    void reauthUnregisteredWebPhoneGivesReauthMismatchNotRegistrationNotApproved() throws Exception {
        // A re-auth on an unregistered phone must be rejected as a reauth mismatch in
        // submitOtp, before (and instead of) the signup/profile branch, even with the
        // web allowlist enabled and this phone absent from it.
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.OTP_SENT);
        session.setDownstreamClient("web");
        session.setReauthUserId("u1");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.empty());

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("reauth_user_mismatch"));
    }

    // --- OTP-send gate (before any SMS is dispatched) ---------------------

    /** Performs POST /login/phone for the standard PHONE with the given session. */
    private org.springframework.test.web.servlet.ResultActions performPhone(LoginSession session) throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        return mockMvc.perform(post("/login/phone")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"phoneNumber\":\"" + PHONE + "\",\"locale\":\"pt-BR\"}"));
    }

    /** Makes the standard PHONE resolve to no account anywhere (unknown number). */
    private void stubPhoneUnknown() {
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.empty());
    }

    @Test
    void otpSendBlockedForUnknownWebNumberBeforeAnySms() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.PHONE);
        session.setDownstreamClient("web");
        stubPhoneUnknown();

        performPhone(session)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("registration_not_approved"))
                .andExpect(jsonPath("$.message").value(
                        "This number is not approved for web sign-up yet. Gua Web is available to Gua beta testers only."));

        // The credit-burn protection: no SMS is ever dispatched for a blocked number.
        verify(otpService, org.mockito.Mockito.never()).sendOtp(any(), any(), any());
    }

    @Test
    void otpSendAllowedForExistingAccountEvenWhenNotAllowlisted() throws Exception {
        // The "app registers, then the web works too" case: a number already in the
        // directory (e.g. registered via the mobile app) is recognised automatically
        // and may receive a login OTP on the web, without being on the allowlist.
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.PHONE);
        session.setDownstreamClient("web");
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(
                DirectoryEntry.builder().phoneDigest("digest").userId("u1").build()));

        performPhone(session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("OTP_SENT"));

        verify(otpService).sendOtp(eq(PHONE), anyString(), eq("pt-BR"));
    }

    @Test
    void otpSendAllowedForAllowlistedWebNumber() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist(PHONE));
        LoginSession session = session(Phase.PHONE);
        session.setDownstreamClient("web");

        performPhone(session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("OTP_SENT"));

        verify(otpService).sendOtp(eq(PHONE), anyString(), eq("pt-BR"));
    }

    @Test
    void otpSendAllowedForNativeFlowRegardlessOfAllowlist() throws Exception {
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.PHONE);
        session.setDownstreamClient("native");
        stubPhoneUnknown();

        performPhone(session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("OTP_SENT"));

        verify(otpService).sendOtp(eq(PHONE), anyString(), eq("pt-BR"));
    }

    @Test
    void otpSendRecognizesExistingAccountViaHomeserverBindingFallback() throws Exception {
        // Directory digest misses (pepper drift) but the homeserver phone binding
        // resolves the returning account: the OTP is still allowed.
        when(properties.getRegistration()).thenReturn(enabledAllowlist("+15559999999"));
        LoginSession session = session(Phase.PHONE);
        session.setDownstreamClient("web");
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.of("@alice:dev.local"));

        performPhone(session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("OTP_SENT"));

        verify(otpService).sendOtp(eq(PHONE), anyString(), eq("pt-BR"));
    }

    @Test
    void otpSendAllowedForUnknownWebNumberWhenGateDisabled() throws Exception {
        // Default registration (disabled) from setUp(): unknown web numbers still get
        // an OTP, i.e. flipping the flag off restores the fully-open flow.
        LoginSession session = session(Phase.PHONE);
        session.setDownstreamClient("web");

        performPhone(session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("OTP_SENT"));

        verify(otpService).sendOtp(eq(PHONE), anyString(), eq("pt-BR"));
    }

    @Test
    void rejectsMissingCsrfToken() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("csrf_failed"));
    }

    @Test
    void rejectsStepOutOfOrder() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));

        mockMvc.perform(post("/login/pin")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"pin\":\"123456\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("unexpected_step"));
    }

    // --- Account genesis attach (ADM-008 decision 6) ---------------------------

    /** Drives a brand-new user to the profile step: no directory row, no homeserver phone binding. */
    private void newUserAtOtpStep() {
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.empty());
    }

    private LoginSession sessionWithHandle(Phase phase, String handle, String challenge) {
        LoginSession session = session(phase);
        session.setGenesisAttachHandle(handle);
        session.setGenesisAttachChallenge(challenge);
        return session;
    }

    private void readyToCreateAccount() {
        when(usernamePolicy.normalizeAndValidate("alice")).thenReturn("alice");
        when(directoryService.isUsernameTaken("alice")).thenReturn(false);
        when(matrixProvisioningService.buildUserId(eq("alice"), any())).thenReturn("@alice:gua.local");
        when(matrixAdminClient.userExists("@alice:gua.local")).thenReturn(false);
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
    }

    @Test
    void enteringTheProfileStepWithAHandleIssuesAnAttachChallenge() throws Exception {
        newUserAtOtpStep();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(
                sessionWithHandle(Phase.OTP_SENT, "the-handle", null)));
        when(accountGenesisService.isEnabled()).thenReturn(true);
        when(accountGenesisService.issueAttachChallenge()).thenReturn("the-challenge");

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PROFILE_REQUIRED"))
                .andExpect(jsonPath("$.genesisAttachChallenge").value("the-challenge"));

        ArgumentCaptor<LoginSession> saved = ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).save(eq(SID), saved.capture());
        assertEquals("the-challenge", saved.getValue().getGenesisAttachChallenge());
    }

    @Test
    void aSessionWithNoHandleIsIssuedNoChallenge() throws Exception {
        newUserAtOtpStep();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(accountGenesisService.isEnabled()).thenReturn(true);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PROFILE_REQUIRED"))
                .andExpect(jsonPath("$.genesisAttachChallenge").doesNotExist());

        verify(accountGenesisService, org.mockito.Mockito.never()).issueAttachChallenge();
    }

    @Test
    void withTheFeatureOffNoChallengeIsIssuedEvenForAHandle() throws Exception {
        newUserAtOtpStep();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(
                sessionWithHandle(Phase.OTP_SENT, "the-handle", null)));

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.genesisAttachChallenge").doesNotExist());

        verify(accountGenesisService, org.mockito.Mockito.never()).issueAttachChallenge();
    }

    @Test
    void aChallengeAlreadyIssuedForThisProfileStepIsNotReplaced() throws Exception {
        newUserAtOtpStep();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(
                sessionWithHandle(Phase.OTP_SENT, "the-handle", "already-issued")));
        when(accountGenesisService.isEnabled()).thenReturn(true);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.genesisAttachChallenge").value("already-issued"));

        verify(accountGenesisService, org.mockito.Mockito.never()).issueAttachChallenge();
    }

    @Test
    void theProfileStepAttachesUsingTheSessionsHandleAndChallengeAndTheRequestsProof() throws Exception {
        readyToCreateAccount();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(
                sessionWithHandle(Phase.PROFILE_REQUIRED, "the-handle", "the-challenge")));
        when(accountGenesisService.isEnabled()).thenReturn(true);

        mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"displayName\":\"Alice A\",\"attachProof\":\"cHJvb2Y\"}"))
                .andExpect(status().isOk());

        // The handle and the challenge come from the server-side session; only the proof is the
        // client's. The account the genesis attaches to is the one just created.
        verify(accountGenesisService).attach("the-handle", "the-challenge", "cHJvb2Y", "@alice:gua.local");
    }

    @Test
    void aFailedAttachFailsTheSignup() throws Exception {
        readyToCreateAccount();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(
                sessionWithHandle(Phase.PROFILE_REQUIRED, "the-handle", "the-challenge")));
        when(accountGenesisService.isEnabled()).thenReturn(true);
        when(accountGenesisService.attach(any(), any(), any(), any()))
                .thenThrow(new LoginFlowException(org.springframework.http.HttpStatus.BAD_REQUEST,
                        "genesis_attach_failed", "This account could not be created. Please try again."));

        mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"displayName\":\"Alice A\",\"attachProof\":\"bad\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("genesis_attach_failed"));

        // No authorization code, and the session is not advanced.
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
        verify(accountGenesisService, org.mockito.Mockito.never()).bootstrap(any());
    }

    @Test
    void aProfileStepWithNoHandleTakesTheBootstrapBranch() throws Exception {
        readyToCreateAccount();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PROFILE_REQUIRED)));
        when(accountGenesisService.isEnabled()).thenReturn(true);

        mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"displayName\":\"Alice A\"}"))
                .andExpect(status().isOk());

        verify(accountGenesisService).bootstrap("@alice:gua.local");
        verify(accountGenesisService, org.mockito.Mockito.never()).attach(any(), any(), any(), any());
    }

    @Test
    void aSuccessfulAttachBurnsTheHandleAndTheChallengeOnTheSession() throws Exception {
        readyToCreateAccount();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(
                sessionWithHandle(Phase.PROFILE_REQUIRED, "the-handle", "the-challenge")));
        when(accountGenesisService.isEnabled()).thenReturn(true);

        mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"displayName\":\"Alice A\",\"attachProof\":\"cHJvb2Y\"}"))
                .andExpect(status().isOk());

        ArgumentCaptor<LoginSession> saved = ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).save(eq(SID), saved.capture());
        assertEquals(null, saved.getValue().getGenesisAttachHandle());
        assertEquals(null, saved.getValue().getGenesisAttachChallenge());
    }

    /**
     * The heal path is the one runtime path that surfaces an account the startup backfill never saw, so
     * it is the one that can push the missing-genesis gauge back above zero between restarts.
     */
    private void recoveredAccountAtOtpStep() {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.of("@alice:dev.local"));
        when(phoneNumberMasker.mask(PHONE)).thenReturn("\u2022\u2022\u2022\u20224567");
        when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(false);
    }

    private org.springframework.test.web.servlet.ResultActions submitOtpForRecoveredAccount() throws Exception {
        return mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"));
    }

    @Test
    void anAccountRecoveredByPhoneBindingIsRootedOnTheSpot() throws Exception {
        recoveredAccountAtOtpStep();
        when(accountGenesisService.isEnabled()).thenReturn(true);

        submitOtpForRecoveredAccount()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.newUser").value(false));

        // Healing the directory row makes this account visible to a later scan; without an id of its own
        // it would sit in gua_identity_accounts_without_genesis until the next restart.
        verify(accountGenesisService).bootstrap("@alice:dev.local");
    }

    @Test
    void aRecoveredAccountIsNotRootedWhileTheFeatureIsOff() throws Exception {
        recoveredAccountAtOtpStep();

        submitOtpForRecoveredAccount().andExpect(status().isOk());

        verify(accountGenesisService, org.mockito.Mockito.never()).bootstrap(any());
    }

    @Test
    void aFailureToRootARecoveredAccountDoesNotBlockTheSignIn() throws Exception {
        recoveredAccountAtOtpStep();
        when(accountGenesisService.isEnabled()).thenReturn(true);
        org.mockito.Mockito.doThrow(new IllegalStateException("transient"))
                .when(accountGenesisService).bootstrap("@alice:dev.local");

        // Best-effort, like the directory heal it follows: a returning user still signs in, and the
        // backfill picks the account up on its next run.
        submitOtpForRecoveredAccount()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"))
                .andExpect(jsonPath("$.newUser").value(false));
    }

    // --- Publishing the factor inventory on the login state --------------

    /**
     * A session that has been asked for its PIN has already had its subject resolved by an OTP,
     * so it can be told what the account holds. That is the whole point: the step where the
     * server decides to ask for the weaker factor is the step where the client most needs to
     * know the stronger one exists.
     */
    @Test
    void loginStateReportsTheAccountFactorsOnceTheSubjectIsResolved() throws Exception {
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey("@alice:dev.local")).thenReturn(true);
        when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(true);

        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_REQUIRED"))
                .andExpect(jsonPath("$.passkeyRegistered").value(true))
                .andExpect(jsonPath("$.preferredFactor").value("PASSKEY"));
    }

    /**
     * The enumeration oracle, and the reason the report is allow-listed by phase rather than
     * merely conditioned on a subject being present. If the phone step could answer "does this
     * account hold a passkey", it would answer for any number anyone submits, for the price of
     * one unverified request. The session here is given a subject it has not earned, and the
     * report must still be absent, and no factor may even be looked up.
     */
    @Test
    void loginStateReportsNothingAtThePhoneStepEvenWhenTheSessionCarriesASubject() throws Exception {
        LoginSession session = session(Phase.PHONE);
        session.setUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        // Enabled, so a report would really consult the repository rather than short-circuit.
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey("@alice:dev.local")).thenReturn(true);
        when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(true);

        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PHONE"))
                .andExpect(jsonPath("$.passkeyRegistered").doesNotExist())
                .andExpect(jsonPath("$.preferredFactor").doesNotExist());

        verify(passkeyService, org.mockito.Mockito.never()).hasPasskey(any());
        verify(userSecurityService, org.mockito.Mockito.never()).hasPin(any());
    }

    /** Same rule one step later: the OTP has been sent, which proves nothing yet. */
    @Test
    void loginStateReportsNothingAtTheOtpStep() throws Exception {
        LoginSession session = session(Phase.OTP_SENT);
        session.setUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey("@alice:dev.local")).thenReturn(true);

        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passkeyRegistered").doesNotExist())
                .andExpect(jsonPath("$.preferredFactor").doesNotExist());

        verify(passkeyService, org.mockito.Mockito.never()).hasPasskey(any());
    }

    /**
     * The oracle stated as the attack rather than as the state: submitting somebody else's
     * number must not come back with what that account holds.
     */
    @Test
    void submittingAPhoneNumberNeverReportsWhatThatAccountHolds() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PHONE)));
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(any())).thenReturn(true);

        mockMvc.perform(post("/login/phone")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"phoneNumber\":\"" + PHONE + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("OTP_SENT"))
                .andExpect(jsonPath("$.passkeyRegistered").doesNotExist())
                .andExpect(jsonPath("$.preferredFactor").doesNotExist());

        verify(passkeyService, org.mockito.Mockito.never()).hasPasskey(any());
    }

    /**
     * The report arrives on the same response that routes the user to the PIN step, so the UI can
     * offer the passkey at the moment it is asked for the PIN without a second round trip.
     */
    @Test
    void routingToThePinStepCarriesTheFactorReport() throws Exception {
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").username("alice")
                .displayName("Alice").build();
        stubReturningDigest(entry);
        when(userSecurityService.hasPin("u1")).thenReturn(true);
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey("u1")).thenReturn(true);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_REQUIRED"))
                .andExpect(jsonPath("$.passkeyRegistered").value(true))
                .andExpect(jsonPath("$.preferredFactor").value("PASSKEY"));
    }

    // --- Reaching the passkey from the PIN step ---------------------------

    @Test
    void passkeyAuthOptionsAreReachableFromThePinStep() throws Exception {
        ObjectNode options = JsonNodeFactory.instance.objectNode();
        options.put("challenge", "abc");
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(passkeyService.startAuthentication(SID)).thenReturn(options);

        mockMvc.perform(post("/login/passkey/auth/options")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey.challenge").value("abc"));
    }

    /**
     * The population this is for: an account with a PIN, which is precisely the one the flow
     * routes to the PIN step and, until now, the one the conflict shut out. Nothing is weakened
     * by letting it in, because the same assertion already completes this same login one step
     * earlier from the phone step.
     */
    @Test
    void passkeyAuthFromThePinStepCompletesWithoutSpendingThePin() throws Exception {
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(true);
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@alice:dev.local", REGISTERED_LONG_AGO));
        DirectoryEntry entry = DirectoryEntry.builder()
                .phoneDigest("digest").userId("@alice:dev.local").username("alice").displayName("Alice").build();
        when(directoryService.findByUserId("@alice:dev.local")).thenReturn(List.of(entry));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.newUser").value(false));

        // The PIN is not consumed, and no failed-guess accounting is charged for using the
        // stronger factor instead of it.
        verify(userSecurityService, org.mockito.Mockito.never()).validatePinOrThrow(any(), any());
    }

    /**
     * A session at the PIN step already knows whose it is, because an OTP proved it. An
     * assertion resolving to somebody else is a different login wearing this session's state, so
     * it is refused before anything is accepted and before the directory is read.
     */
    @Test
    void passkeyAuthFromThePinStepRefusesAnAssertionForAnotherAccount() throws Exception {
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@bob:dev.local", REGISTERED_LONG_AGO));

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("passkey_user_mismatch"));

        verify(directoryService, org.mockito.Mockito.never()).findByUserId(any());
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    /** The phone-keyed directory row stays required from the newly admitted step too. */
    @Test
    void passkeyAuthFromThePinStepStillRequiresAPhoneKeyedDirectoryRow() throws Exception {
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@alice:dev.local", REGISTERED_LONG_AGO));
        DirectoryEntry rowWithoutPhone = DirectoryEntry.builder()
                .userId("@alice:dev.local").username("alice").displayName("Alice").build();
        when(directoryService.findByUserId("@alice:dev.local")).thenReturn(List.of(rowWithoutPhone));

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("passkey_user_not_registered"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    /**
     * Widening the phase set must not reach the step that belongs to an account which does not
     * exist yet, or an assertion would be a route into account creation.
     */
    @Test
    void passkeyAuthIsNotReachableFromTheProfileStep() throws Exception {
        LoginSession session = session(Phase.PROFILE_REQUIRED);
        session.setNewUser(true);
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/passkey/auth/options")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("unexpected_step"));

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("unexpected_step"));

        verify(passkeyService, org.mockito.Mockito.never()).startAuthentication(any());
        verify(passkeyService, org.mockito.Mockito.never()).finishAuthentication(any(), any());
        verify(directoryService, org.mockito.Mockito.never()).upsertByDigest(any(), any(), any(), any());
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    /**
     * An enrollment session carries no OIDC request, so it has no authorization code to issue and
     * must never enter the sign-in ceremony. Refused by name rather than by step, so a later
     * widening of the phase set cannot turn an enrollment into a login.
     */
    @Test
    void passkeyAuthIsNotReachableFromAnEnrollmentSession() throws Exception {
        LoginSession session = enrollSession();
        session.setPhase(Phase.PIN_REQUIRED);
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/passkey/auth/options")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("enroll_session_cannot_sign_in"));

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("enroll_session_cannot_sign_in"));

        verify(passkeyService, org.mockito.Mockito.never()).finishAuthentication(any(), any());
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    /** The double-submit check still runs first on the newly reachable step. */
    @Test
    void passkeyAuthFromThePinStepStillRequiresTheCsrfToken() throws Exception {
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("@alice:dev.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/passkey/auth/verify")
                .cookie(cookie())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("csrf_failed"));

        verify(passkeyService, org.mockito.Mockito.never()).finishAuthentication(any(), any());
    }

    // --- Signup order: passkey first, PIN as the fallback -----------------

    @Test
    void submitProfileOffersThePasskeyBeforeAskingForAPin() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PROFILE_REQUIRED)));
        when(usernamePolicy.normalizeAndValidate("Alice")).thenReturn("alice");
        when(directoryService.isUsernameTaken("alice")).thenReturn(false);
        when(matrixProvisioningService.buildUserId(eq("alice"), any())).thenReturn("@alice:gua.local");
        when(matrixAdminClient.userExists("@alice:gua.local")).thenReturn(false);
        when(passkeyService.isEnabled()).thenReturn(true);

        mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"Alice\",\"displayName\":\"Alice A\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"))
                .andExpect(jsonPath("$.newUser").value(true));

        verify(userSecurityService, org.mockito.Mockito.never()).setInitialPin(any(), any());
    }

    /**
     * The one kind of unavailability the server establishes on its own, from configuration
     * rather than from anything a caller says: this deployment cannot run a passkey ceremony at
     * all, so the account is asked for the fallback directly instead of being shown an offer
     * that would only fail.
     */
    @Test
    void submitProfileFallsStraightToPinSetupWhenTheDeploymentHasNoPasskeys() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PROFILE_REQUIRED)));
        when(usernamePolicy.normalizeAndValidate("Alice")).thenReturn("alice");
        when(directoryService.isUsernameTaken("alice")).thenReturn(false);
        when(matrixProvisioningService.buildUserId(eq("alice"), any())).thenReturn("@alice:gua.local");
        when(matrixAdminClient.userExists("@alice:gua.local")).thenReturn(false);
        when(passkeyService.isEnabled()).thenReturn(false);

        mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"Alice\",\"displayName\":\"Alice A\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));
    }

    /**
     * Declined, failed, or impossible on this device all arrive at the same endpoint, and all of
     * them must land on the PIN step. Completing here instead would finish onboarding with no
     * second factor at all, which is the outcome the PIN exists to prevent.
     */
    @Test
    void decliningThePasskeyDuringSignupRoutesToPinSetupAndNeverToCompletion() throws Exception {
        LoginSession session = newAccountAtPasskeySetup();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/passkey/setup-skip")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    /**
     * A ceremony that fails leaves the session where it was, so the same door is still open: the
     * client retries or gives up, and giving up reaches the PIN step rather than the end.
     */
    @Test
    void aFailedPasskeyCeremonyDuringSignupStillReachesPinSetup() throws Exception {
        LoginSession session = newAccountAtPasskeySetup();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        org.mockito.Mockito.doThrow(new LoginFlowException(org.springframework.http.HttpStatus.BAD_REQUEST,
                "passkey_registration_failed", "Passkey setup was not accepted. Please try again."))
                .when(loginFactorEnrollmentService).registerPasskey(eq(SID), eq(session), any());

        mockMvc.perform(post("/login/passkey/register/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("passkey_registration_failed"));

        mockMvc.perform(post("/login/passkey/setup-skip")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    /**
     * The product rule in one test: a new account that registers a passkey is finished. It is
     * never asked for a PIN, because the PIN is the fallback for whoever could not do this.
     */
    @Test
    void registeringThePasskeyDuringSignupCompletesWithNoPinDemanded() throws Exception {
        LoginSession session = newAccountAtPasskeySetup();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(loginFactorEnrollmentService.registerPasskey(eq(SID), eq(session), any())).thenReturn(true);
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/passkey/register/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"));

        verify(userSecurityService, org.mockito.Mockito.never()).setInitialPin(any(), any());
    }

    /**
     * A returning account reaches the offer at the end of a PIN sign-in, and is done when it
     * declines, exactly as before.
     */
    @Test
    void decliningThePasskeyAsAReturningUserStillCompletes() throws Exception {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
        session.setNewUser(false);
        session.setAuthenticatedFactor(SessionFactor.PIN);
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/passkey/setup-skip")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"));
    }

    /** The PIN step keeps its own double-submit check, which is the only way into it. */
    @Test
    void pinSetupStillRequiresTheCsrfToken() throws Exception {
        LoginSession session = session(Phase.PIN_SETUP);
        session.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/pin-setup")
                .cookie(cookie())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"pin\":\"123456\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("csrf_failed"));

        verify(loginFactorEnrollmentService, org.mockito.Mockito.never()).setUpFirstPin(any(), any());
    }

    /** A brand-new account sitting at the passkey offer, which is where signup now goes first. */
    private LoginSession newAccountAtPasskeySetup() {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
        session.setPreferredUsername("alice");
        session.setNewUser(true);
        return session;
    }

    // --- D1: PASSKEY_REQUIRED ---------------------------------------------

    /** An account holding a passkey and no PIN, at the OTP step. */
    private void passkeyOnlyAccountAtOtpStep(boolean deploymentHasPasskeys) {
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("@alice:dev.local")
                .username("alice").displayName("Alice").build();
        stubReturningDigest(entry);
        when(passkeyService.isEnabled()).thenReturn(deploymentHasPasskeys);
        when(passkeyService.hasPasskey("@alice:dev.local")).thenReturn(true);
        when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(false);
    }

    private LoginSession passkeyRequiredSession() {
        LoginSession session = session(Phase.PASSKEY_REQUIRED);
        session.setUserId("@alice:dev.local");
        session.setPreferredUsername("alice");
        session.setOtpVerified(true);
        return session;
    }

    private org.springframework.test.web.servlet.ResultActions postJson(String path, String body) throws Exception {
        return mockMvc.perform(post(path)
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    @Test
    void anSmsCodeRoutesAPasskeyOnlyAccountToPasskeyRequiredAndIssuesNoCode() throws Exception {
        passkeyOnlyAccountAtOtpStep(true);

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_REQUIRED"))
                .andExpect(jsonPath("$.passkeyRegistered").value(true))
                .andExpect(jsonPath("$.preferredFactor").value("PASSKEY"))
                .andExpect(jsonPath("$.passkeysEnabled").value(true))
                .andExpect(jsonPath("$.redirectUrl").doesNotExist());

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
        verify(userSecurityService, org.mockito.Mockito.never()).recordSuccessfulLogin(any());
    }

    /**
     * The stored-credential predicate. With passkeys switched off the account cannot present its
     * passkey, and it must still not be finished by the SMS code or routed to a PIN it would get
     * to choose. The UI is told the deployment cannot run the ceremony, so it leads with recovery.
     */
    @Test
    void aStoredPasskeyStillGatesTheSignInWhenTheDeploymentHasPasskeysSwitchedOff() throws Exception {
        passkeyOnlyAccountAtOtpStep(false);

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_REQUIRED"))
                .andExpect(jsonPath("$.passkeysEnabled").value(false))
                .andExpect(jsonPath("$.passkeyRegistered").value(false));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
        verify(loginFactorEnrollmentService, org.mockito.Mockito.never()).setUpFirstPin(any(), any());
    }

    @Test
    void thePinStepIsRefusedAtPasskeyRequired() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(passkeyRequiredSession()));

        postJson("/login/pin", "{\"pin\":\"284917\"}")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("unexpected_step"));
        postJson("/login/pin-setup", "{\"pin\":\"284917\"}")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("unexpected_step"));
        postJson("/login/passkey/setup-skip", "{}")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("unexpected_step"));

        verify(userSecurityService, org.mockito.Mockito.never()).validatePinOrThrow(any(), any());
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void thePasskeyAssertionIsReachableFromPasskeyRequiredAndCompletesWithIt() throws Exception {
        LoginSession session = passkeyRequiredSession();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        ObjectNode options = JsonNodeFactory.instance.objectNode();
        options.put("challenge", "abc");
        when(passkeyService.startAuthentication(SID)).thenReturn(options);
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@alice:dev.local", REGISTERED_LONG_AGO));
        when(directoryService.findByUserId("@alice:dev.local")).thenReturn(List.of(DirectoryEntry.builder()
                .phoneDigest("digest").userId("@alice:dev.local").username("alice").displayName("Alice").build()));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        postJson("/login/passkey/auth/options", "{}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey.challenge").value("abc"));
        postJson("/login/passkey/auth/verify", "{\"credential\":{\"id\":\"cred-1\"}}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"));

        assertEquals(SessionFactor.PASSKEY, session.getAuthenticatedFactor());
        assertEquals(false, issuedAuthorization().endOtherSessions());
    }

    @Test
    void anAssertionForAnotherAccountIsRefusedAtPasskeyRequired() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(passkeyRequiredSession()));
        when(passkeyService.finishAuthentication(eq(SID), any()))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@bob:dev.local", REGISTERED_LONG_AGO));

        postJson("/login/passkey/auth/verify", "{\"credential\":{\"id\":\"cred-1\"}}")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("passkey_user_mismatch"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    // --- complete() guard and the ENROLLED race ----------------------------

    /**
     * The backstop. Every route sets the factor before completing; this proves the completion
     * itself refuses when one does not, whatever the route claimed.
     */
    @Test
    void completionIsRefusedForASessionThatHasNotAuthenticatedWithAFactor() throws Exception {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        // A registration that did not create the account's first factor, for a session holding none.
        when(loginFactorEnrollmentService.registerPasskey(eq(SID), eq(session), any())).thenReturn(false);

        postJson("/login/passkey/register/verify", "{\"credential\":{\"id\":\"cred-1\"}}")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("factor_required"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
        verify(userSecurityService, org.mockito.Mockito.never()).recordSuccessfulLogin(any());
        verify(loginSessionService, org.mockito.Mockito.never()).delete(any());
    }

    /** A session persisted before the factor field existed carries none, and gets factor_required. */
    @Test
    void aSessionFromBeforeTheRolloutCannotFinishFromPasskeySetup() throws Exception {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        postJson("/login/passkey/setup-skip", "{}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PIN_SETUP"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    /**
     * Two sessions for one factorless account both reach setup. The one that finishes second
     * finds, under the row lock, a factor it did not authenticate with, and is refused before
     * storing its own.
     */
    @Test
    void theSecondSessionToSetAFactorOnTheSameAccountIsRefused() throws Exception {
        LoginSession pinSetup = session(Phase.PIN_SETUP);
        pinSetup.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(pinSetup));
        org.mockito.Mockito.doThrow(new LoginFlowException(org.springframework.http.HttpStatus.CONFLICT,
                "factor_required", "This account is already protected."))
                .when(loginFactorEnrollmentService).setUpFirstPin("@alice:gua.local", "284917");

        postJson("/login/pin-setup", "{\"pin\":\"284917\"}")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("factor_required"));

        LoginSession passkeySetup = session(Phase.PASSKEY_SETUP);
        passkeySetup.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(passkeySetup));
        when(loginFactorEnrollmentService.registerPasskey(eq(SID), eq(passkeySetup), any()))
                .thenThrow(new LoginFlowException(org.springframework.http.HttpStatus.CONFLICT,
                        "factor_required", "This account is already protected."));

        postJson("/login/passkey/register/verify", "{\"credential\":{\"id\":\"cred-1\"}}")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("factor_required"));

        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
        assertEquals(null, pinSetup.getAuthenticatedFactor());
        assertEquals(null, passkeySetup.getAuthenticatedFactor());
    }

    /** A PIN sign-in that registers a passkey afterwards keeps PIN as the factor it earned. */
    @Test
    void registeringAPasskeyAfterAPinSignInKeepsThePinAsTheSessionFactor() throws Exception {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
        session.setAuthenticatedFactor(SessionFactor.PIN);
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(loginFactorEnrollmentService.registerPasskey(eq(SID), eq(session), any())).thenReturn(false);
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        postJson("/login/passkey/register/verify", "{\"credential\":{\"id\":\"cred-1\"}}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"));

        assertEquals(SessionFactor.PIN, session.getAuthenticatedFactor());
    }

    // --- Delayed account recovery ------------------------------------------

    private LoginSession pinRequiredSessionAfterOtp() {
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("@alice:dev.local");
        session.setPreferredUsername("alice");
        session.setOtpVerified(true);
        return session;
    }

    private static final AccountRecoveryState PENDING = new AccountRecoveryState(
            AccountRecoveryState.Status.PENDING, null, 1_760_000_000L, 1_760_604_800L);

    @Test
    void theFactorStepsPublishTheRecoveryStateAfterAnOtp() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(passkeyRequiredSession()));
        when(accountRecoveryService.stateFor("@alice:dev.local")).thenReturn(PENDING);

        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_REQUIRED"))
                .andExpect(jsonPath("$.enrollment").value(false))
                .andExpect(jsonPath("$.recovery.status").value("PENDING"))
                .andExpect(jsonPath("$.recovery.completableAtEpochSeconds").value(1_760_000_000L))
                .andExpect(jsonPath("$.recovery.expiresAtEpochSeconds").value(1_760_604_800L))
                .andExpect(jsonPath("$.recovery.availableAtEpochSeconds").doesNotExist());

        when(loginSessionService.find(SID)).thenReturn(Optional.of(pinRequiredSessionAfterOtp()));
        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recovery.status").value("PENDING"));
    }

    /** Every condition recovery needs, each one taken away in turn. */
    @Test
    void recoveryIsUnavailableOutsideAFactorStepReachedByOtp() throws Exception {
        LoginSession noOtp = passkeyRequiredSession();
        noOtp.setOtpVerified(false);

        LoginSession reauth = pinRequiredSessionAfterOtp();
        reauth.setReauthUserId("@alice:dev.local");

        LoginSession enrollment = enrollSession();
        enrollment.setOtpVerified(true);
        enrollment.setPhase(Phase.PIN_REQUIRED);

        // A passkey-first sign-in has not proved the number.
        LoginSession passkeyFirst = session(Phase.PHONE);
        passkeyFirst.setIntent(LoginSession.Intent.PASSKEY);
        passkeyFirst.setUserId("@alice:dev.local");

        LoginSession wrongStep = pinRequiredSessionAfterOtp();
        wrongStep.setPhase(Phase.PIN_SETUP);

        LoginSession noSubject = pinRequiredSessionAfterOtp();
        noSubject.setUserId(null);

        for (LoginSession session : List.of(noOtp, reauth, enrollment, passkeyFirst, wrongStep, noSubject)) {
            when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

            mockMvc.perform(get("/login/context").cookie(cookie()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.recovery").doesNotExist());
            postJson("/login/recovery/start", "{}")
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.code").value("recovery_unavailable"));
            postJson("/login/recovery/complete", "{\"newPin\":\"284917\"}")
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.code").value("recovery_unavailable"));
        }

        org.mockito.Mockito.verifyNoInteractions(accountRecoveryService, tokenRevocationService);
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void startingRecoveryOpensTheEpisodeAndReturnsTheState() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(passkeyRequiredSession()));
        when(phoneNumberMasker.mask(PHONE)).thenReturn("••••4567");
        when(accountRecoveryService.stateFor("@alice:dev.local")).thenReturn(PENDING);

        postJson("/login/recovery/start", "{}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_REQUIRED"))
                .andExpect(jsonPath("$.recovery.status").value("PENDING"));

        verify(accountRecoveryService).start("@alice:dev.local", "••••4567", "127.0.0.1");
        // Recovery sends no SMS.
        verify(otpService, org.mockito.Mockito.never()).sendOtp(any(), any(), any());
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
    }

    @Test
    void startingRecoveryOnARecentlyUsedAccountIsACooldownWithRetryAfter() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(pinRequiredSessionAfterOtp()));
        when(accountRecoveryService.start(eq("@alice:dev.local"), any(), any()))
                .thenThrow(new AccountRecoveryCooldownException("Account recovery cannot be started yet", 3600L));

        postJson("/login/recovery/start", "{}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("recovery_cooldown_active"))
                .andExpect(jsonPath("$.retryAfterSeconds").value(3600))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                        .string("Retry-After", "3600"));
    }

    /** E1, E2: a completed recovery revokes this service's tokens and marks the ID token. */
    @Test
    void completingRecoveryIssuesACodeWhoseTokensEndEveryOtherSession() throws Exception {
        LoginSession session = passkeyRequiredSession();
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        postJson("/login/recovery/complete", "{\"newPin\":\" 284917 \"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.redirectUrl").value(CALLBACK + "?code=auth-code&state=xyz"));

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(accountRecoveryService, tokenRevocationService,
                authorizationService);
        order.verify(accountRecoveryService).complete("@alice:dev.local", "284917");
        order.verify(tokenRevocationService).revokeAllTokens("@alice:dev.local");
        order.verify(authorizationService).issueCode(any(), eq(CALLBACK), any());
        assertEquals(SessionFactor.RECOVERY, session.getAuthenticatedFactor());
        assertEquals(true, issuedAuthorization().endOtherSessions());
    }

    @Test
    void completingARecoveryThatIsNotReadyReturnsTheFreshStateAndIssuesNothing() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(pinRequiredSessionAfterOtp()));
        org.mockito.Mockito.doThrow(new AccountRecoveryNotReadyException("Account recovery is not ready to complete",
                new AccountRecoveryState(AccountRecoveryState.Status.AVAILABLE, null, null, null)))
                .when(accountRecoveryService).complete("@alice:dev.local", "284917");

        postJson("/login/recovery/complete", "{\"newPin\":\"284917\"}")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("recovery_not_ready"))
                .andExpect(jsonPath("$.recovery.status").value("AVAILABLE"));

        org.mockito.Mockito.verifyNoInteractions(tokenRevocationService);
        verify(authorizationService, org.mockito.Mockito.never()).issueCode(any(), any(), any());
        verify(userSecurityService, org.mockito.Mockito.never()).recordSuccessfulLogin(any());
    }

    @Test
    void theRecoveryEndpointsCheckTheCsrfToken() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(passkeyRequiredSession()));

        for (String path : new String[] { "/login/recovery/start", "/login/recovery/complete" }) {
            mockMvc.perform(post(path)
                    .cookie(cookie())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"newPin\":\"284917\"}"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code").value("csrf_failed"));
        }

        org.mockito.Mockito.verifyNoInteractions(accountRecoveryService, tokenRevocationService);
    }

    @Test
    void anEnrollmentSessionSaysSoOnItsState() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(enrollSession()));

        mockMvc.perform(get("/login/context").cookie(cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enrollment").value(true));
    }
}
