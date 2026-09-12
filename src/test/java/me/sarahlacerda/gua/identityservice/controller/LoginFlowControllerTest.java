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
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(LoginFlowController.class)
@AutoConfigureMockMvc(addFilters = false)
@AutoConfigureObservability   // provide a MeterRegistry in the slice (micrometer-prometheus is on the classpath)
@org.springframework.context.annotation.Import(LoginFlowControllerTest.GuardConfig.class)
class LoginFlowControllerTest {

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
        when(userSecurityService.hasPin("u1")).thenReturn(false);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"));
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

    @Test
    void submitOtpForReturningUserWithoutPinRoutesToPasskeySetup() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").username("alice")
                .displayName("Alice").build();
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));
        when(userSecurityService.hasPin("u1")).thenReturn(false);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"));

        verify(otpService).verifyOtp(PHONE, "123456");
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
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"))
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

    @Test
    void submitPinSetupWithPinSetsItAndRoutesToPasskeySetup() throws Exception {
        LoginSession session = session(Phase.PIN_SETUP);
        session.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/pin-setup")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"pin\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"));

        verify(userSecurityService).setInitialPin("@alice:gua.local", "123456");
    }

    @Test
    void submitPinSetupSkipRoutesToPasskeySetupWithoutPin() throws Exception {
        LoginSession session = session(Phase.PIN_SETUP);
        session.setUserId("@alice:gua.local");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));

        mockMvc.perform(post("/login/pin-setup")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"skip\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"));

        verify(userSecurityService, org.mockito.Mockito.never()).setInitialPin(any(), any());
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
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());

        mockMvc.perform(post("/login/passkey/register/verify")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"credential\":{\"id\":\"cred-1\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.redirectUrl").value(CALLBACK + "?code=auth-code&state=xyz"));

        verify(passkeyService).finishRegistration(eq(SID), eq(session), any());
    }

    @Test
    void passkeySetupSkipCompletesLogin() throws Exception {
        LoginSession session = session(Phase.PASSKEY_SETUP);
        session.setUserId("@alice:gua.local");
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
                .thenReturn(new PasskeyService.PasskeyAuthentication("@alice:dev.local"));
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
                .thenReturn(new PasskeyService.PasskeyAuthentication("@ghost:dev.local"));
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
                .thenReturn(new PasskeyService.PasskeyAuthentication("@bob:dev.local"));
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
                .thenReturn(new PasskeyService.PasskeyAuthentication("@alice:dev.local"));
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
                .thenReturn(new PasskeyService.PasskeyAuthentication("ga1abc:x"));
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

    /** Lets a returning login finish in one call: the account already has a passkey. */
    private void stubAccountAlreadyHasPasskey(String userId) {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(userId)).thenReturn(true);
        when(authorizationService.issueCode(any(), eq(CALLBACK), any())).thenReturn(issuedCode());
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
                .andExpect(jsonPath("$.phase").value("COMPLETED"));

        OidcAuthorization authorization = issuedAuthorization();
        // sub stays the MXID; the localpart is the stored username, not the MXID's.
        assertEquals("@alice:dev.local", authorization.userId());
        assertEquals("alice.s", authorization.preferredUsername());
    }

    /** The S6 trap: a re-keyed, colon-bearing user_id must not change what MAS is told. */
    @Test
    void returningUserWithReKeyedUserIdStillEmitsTheStoredUsername() throws Exception {
        stubReturningDigest(DirectoryEntry.builder().phoneDigest("digest").userId("ga1abc:x")
                .username("alice").displayName("Alice").build());
        stubAccountAlreadyHasPasskey("ga1abc:x");

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"));

        assertEquals("alice", issuedAuthorization().preferredUsername());
    }

    @Test
    void returningUserWithoutStoredUsernameEmitsTheMxidLocalpart() throws Exception {
        stubReturningDigest(DirectoryEntry.builder().phoneDigest("digest").userId("@alice:dev.local")
                .displayName("Alice").build());
        stubAccountAlreadyHasPasskey("@alice:dev.local");

        performOtp()
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("COMPLETED"));

        assertEquals("alice", issuedAuthorization().preferredUsername());
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
                .andExpect(jsonPath("$.phase").value("COMPLETED"))
                .andExpect(jsonPath("$.newUser").value(false));

        assertEquals("alice", issuedAuthorization().preferredUsername());
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
        when(userSecurityService.hasPin("u1")).thenReturn(false);

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"))
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
                .andExpect(jsonPath("$.phase").value("PASSKEY_SETUP"))
                .andExpect(jsonPath("$.newUser").value(false));
    }
}
