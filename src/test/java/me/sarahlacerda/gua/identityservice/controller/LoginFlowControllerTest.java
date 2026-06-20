package me.sarahlacerda.gua.identityservice.controller;

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
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.MatrixProvisioningService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberNormalizer;
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
class LoginFlowControllerTest {

    private static final String SID = "session-id";
    private static final String CSRF = "csrf-token";
    private static final String CALLBACK = "https://mas.example.com/callback";
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

    @BeforeEach
    void setUp() {
        when(properties.getCookieName()).thenReturn("gua_login");
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
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").displayName("Alice").build();
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
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").displayName("Alice").build();
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
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").displayName("Alice").build();
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

    @Test
    void passkeyAuthenticationIsDisabledBeforePhoneVerification() throws Exception {
        mockMvc.perform(post("/login/passkey/auth/options")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("passkey_auth_disabled"));
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
}
