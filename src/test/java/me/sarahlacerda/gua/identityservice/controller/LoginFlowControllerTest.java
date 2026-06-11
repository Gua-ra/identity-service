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
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.controller.oidc.LoginFlowController;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
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
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(LoginFlowController.class)
@AutoConfigureMockMvc(addFilters = false)
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
    private EndpointRateLimiter endpointRateLimiter;

    @BeforeEach
    void setUp() {
        when(properties.getCookieName()).thenReturn("gua_login");
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
    void submitOtpForReturningUserWithoutPinCompletes() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.OTP_SENT)));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        DirectoryEntry entry = DirectoryEntry.builder().phoneDigest("digest").userId("u1").displayName("Alice").build();
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(entry));
        when(userSecurityService.hasPin("u1")).thenReturn(false);
        when(authorizationService.issueCode(any(), eq(CALLBACK), any()))
            .thenReturn(issuedCode());

        mockMvc.perform(post("/login/otp")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.phase").value("COMPLETED"))
            .andExpect(jsonPath("$.redirectUrl").value(CALLBACK + "?code=auth-code&state=xyz"));

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
    void submitPinCompletesForReturningUser() throws Exception {
        LoginSession session = session(Phase.PIN_REQUIRED);
        session.setUserId("u1");
        session.setDisplayName("Alice");
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session));
        when(authorizationService.issueCode(any(), eq(CALLBACK), any()))
            .thenReturn(issuedCode());

        mockMvc.perform(post("/login/pin")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"pin\":\"123456\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.phase").value("COMPLETED"));

        verify(userSecurityService).validatePinOrThrow("u1", "123456");
    }

    @Test
    void submitProfileReservesUsernameAndCompletes() throws Exception {
        when(loginSessionService.find(SID)).thenReturn(Optional.of(session(Phase.PROFILE_REQUIRED)));
        when(usernamePolicy.normalizeAndValidate("Alice")).thenReturn("alice");
        when(matrixProvisioningService.buildUserId("alice")).thenReturn("@alice:gua.local");
        when(matrixAdminClient.userExists("@alice:gua.local")).thenReturn(false);
        when(matrixProvisioningService.generateOpaqueUserId()).thenReturn("opaque-1");
        when(authorizationService.issueCode(any(), eq(CALLBACK), any()))
            .thenReturn(issuedCode());

        mockMvc.perform(post("/login/profile")
                .cookie(cookie())
                .header("X-CSRF-Token", CSRF)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"Alice\",\"displayName\":\"Alice A\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.phase").value("COMPLETED"));

        verify(directoryService).upsertByDigest(any(), eq("opaque-1"), eq("Alice A"));
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
