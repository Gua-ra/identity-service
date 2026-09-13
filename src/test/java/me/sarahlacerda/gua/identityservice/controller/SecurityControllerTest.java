package me.sarahlacerda.gua.identityservice.controller;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;

import me.sarahlacerda.gua.identityservice.controller.security.SecurityController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeStartRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinUpdateRequest;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.AccountLocalpartResolver;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactorPolicy;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.PinChangeService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class SecurityControllerTest {

    @Mock
    private UserSecurityService userSecurityService;

    @Mock
    private AuthenticatedUserAccessor authenticatedUserAccessor;

    @Mock
    private DirectoryService directoryService;

    @Mock
    private LoginSessionService loginSessionService;

    @Mock
    private PasskeyService passkeyService;

    @Mock
    private PinChangeService pinChangeService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;
    private IdentityServiceProperties properties;
    private LoginFlowProperties loginProperties;
    private OidcProperties oidcProperties;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        properties = new IdentityServiceProperties();
        loginProperties = new LoginFlowProperties();
        oidcProperties = new OidcProperties();
        oidcProperties.setIssuer("https://auth.example.com");
        SecurityController controller = new SecurityController(userSecurityService, authenticatedUserAccessor,
                properties, directoryService, loginSessionService, loginProperties, oidcProperties, passkeyService,
                // Real policy over the mocked services, so the factor report and the enrollment
                // guard are the ones the application computes.
                new AuthFactorPolicy(userSecurityService, passkeyService),
                new AccountLocalpartResolver(directoryService), pinChangeService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new RestExceptionHandler())
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    @Test
    void setPinRequiresAuthentication() throws Exception {
        PinUpdateRequest request = new PinUpdateRequest();
        request.setUserId("@user:domain");
        request.setNewPin("123456");

        doNothing().when(authenticatedUserAccessor).requireUserIdMatches("@user:domain");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isNoContent());

        verify(userSecurityService).setInitialPin("@user:domain", "123456");
    }

    @Test
    void requestPinResetDelegatesToService() throws Exception {
        PinResetRequest request = new PinResetRequest();
        request.setUserId("@user:domain");
        request.setPhone("+12025550123");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/reset")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isAccepted());

        verify(userSecurityService).requestPinReset("@user:domain", "+12025550123", "127.0.0.1");
    }

    @Test
    void completePinResetDelegatesToService() throws Exception {
        PinResetCompleteRequest request = new PinResetCompleteRequest();
        request.setUserId("@user:domain");
        request.setPhone("+12025550123");
        request.setCode("876543");
        request.setNewPin("123456");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/reset/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isNoContent());

        verify(userSecurityService).completePinReset("@user:domain", "+12025550123", "876543", "123456");
    }

    @Test
    void startPinChangeReturnsChallenge() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(pinChangeService.start(
                org.mockito.ArgumentMatchers.eq("@user:domain"),
                org.mockito.ArgumentMatchers.eq("+12025550123"),
                org.mockito.ArgumentMatchers.eq("123456"),
                org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn("chal-1");

        PinChangeStartRequest request = new PinChangeStartRequest();
        request.setPhone("+12025550123");
        request.setCurrentPin("123456");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/change/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.challengeId")
                        .value("chal-1"));
    }

    @Test
    void startPinChangePassesThePasskeyAssertionThrough() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(pinChangeService.start(
                org.mockito.ArgumentMatchers.eq("@user:domain"),
                org.mockito.ArgumentMatchers.eq("+12025550123"),
                org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.eq("step-1"),
                org.mockito.ArgumentMatchers.argThat(node -> node != null && "cred-1".equals(node.path("id").asText())),
                org.mockito.ArgumentMatchers.anyString())).thenReturn("chal-2");

        // No currentPin at all: with an assertion supplied the PIN is not a required field.
        String body = "{\"phone\":\"+12025550123\",\"passkeyStepUpId\":\"step-1\",\"passkeyCredential\":{\"id\":\"cred-1\"}}";
        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/change/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.challengeId")
                        .value("chal-2"));
    }

    @Test
    void completePinChangeDelegatesToService() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");

        PinChangeCompleteRequest request = new PinChangeCompleteRequest();
        request.setChallengeId("chal-1");
        request.setOtpCode("987654");
        request.setNewPin("654321");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/change/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isNoContent());

        verify(userSecurityService).completePinChange("@user:domain", "chal-1", "987654", "654321");
    }

    @Test
    void setPinRejectsCurrentPinPayload() throws Exception {
        PinUpdateRequest request = new PinUpdateRequest();
        request.setUserId("@user:domain");
        request.setNewPin("654321");
        request.setCurrentPin("123456");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(
                        org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().is4xxClientError());

        org.mockito.Mockito.verify(userSecurityService, org.mockito.Mockito.never())
                .setInitialPin(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void startPasskeyEnrollmentReturnsAbsoluteEnrollUrl() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");
        org.mockito.Mockito.when(directoryService.findByUserId("@alice:dev.local"))
                .thenReturn(java.util.List.of(
                        DirectoryEntry.builder().userId("@alice:dev.local").displayName("Alice").build()));
        org.mockito.Mockito.when(loginSessionService.create(org.mockito.ArgumentMatchers.any(LoginSession.class)))
                .thenReturn("sess-1");
        org.mockito.Mockito.when(loginSessionService.newToken()).thenReturn("csrf-1");
        org.mockito.Mockito.when(loginSessionService.createEnrollToken(
                org.mockito.ArgumentMatchers.eq("sess-1"), org.mockito.ArgumentMatchers.any()))
                .thenReturn("tok-1");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/passkey/enroll/start")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.enrollUrl")
                        .value("https://auth.example.com/login/passkey/enroll/tok-1"));
    }

    @Test
    void startPasskeyEnrollmentPinsSessionToAuthenticatedUserInPasskeySetup() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");
        // Empty directory result -> display name falls back to the MXID localpart.
        org.mockito.Mockito.when(directoryService.findByUserId("@alice:dev.local"))
                .thenReturn(java.util.List.of());
        org.mockito.Mockito.when(loginSessionService.create(org.mockito.ArgumentMatchers.any(LoginSession.class)))
                .thenReturn("sess-1");
        org.mockito.Mockito.when(loginSessionService.newToken()).thenReturn("csrf-1");
        org.mockito.Mockito.when(loginSessionService.createEnrollToken(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any())).thenReturn("tok-1");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/passkey/enroll/start")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        org.mockito.ArgumentCaptor<LoginSession> captor = org.mockito.ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).create(captor.capture());
        LoginSession created = captor.getValue();
        org.junit.jupiter.api.Assertions.assertEquals(LoginSession.Phase.PASSKEY_SETUP, created.getPhase());
        org.junit.jupiter.api.Assertions.assertEquals("@alice:dev.local", created.getUserId());
        org.junit.jupiter.api.Assertions.assertEquals("@alice:dev.local", created.getReauthUserId());
        org.junit.jupiter.api.Assertions.assertEquals("global.gua:/oidc", created.getRedirectUri());
        org.junit.jupiter.api.Assertions.assertEquals("csrf-1", created.getCsrfToken());
        // No directory display name -> localpart fallback.
        org.junit.jupiter.api.Assertions.assertEquals("alice", created.getDisplayName());
        org.junit.jupiter.api.Assertions.assertEquals("alice", created.getPreferredUsername());
    }

    @Test
    void startPasskeyEnrollmentUsesTheStoredUsername() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");
        org.mockito.Mockito.when(directoryService.findByUserId("@alice:dev.local"))
                .thenReturn(java.util.List.of(
                        DirectoryEntry.builder().userId("@alice:dev.local").username("alice.s").build()));
        org.mockito.Mockito.when(loginSessionService.create(org.mockito.ArgumentMatchers.any(LoginSession.class)))
                .thenReturn("sess-1");
        org.mockito.Mockito.when(loginSessionService.newToken()).thenReturn("csrf-1");
        org.mockito.Mockito.when(loginSessionService.createEnrollToken(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any())).thenReturn("tok-1");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/passkey/enroll/start")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        org.mockito.ArgumentCaptor<LoginSession> captor = org.mockito.ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).create(captor.capture());
        org.junit.jupiter.api.Assertions.assertEquals("alice.s", captor.getValue().getPreferredUsername());
        // No directory display name: the stored username stands in.
        org.junit.jupiter.api.Assertions.assertEquals("alice.s", captor.getValue().getDisplayName());
    }

    @Test
    void pinStatusReportsTheFreshTwoFactorHoldTheClientsPreCheck() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(userSecurityService.hasPin("@user:domain")).thenReturn(true);
        org.mockito.Mockito.when(userSecurityService.changePhonePinHoldRemainingSeconds("@user:domain"))
                .thenReturn(432000L);

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.hasPin")
                        .value(true))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.changePhoneCooldownRemainingSeconds").value(432000));
    }

    @Test
    void pinStatusReportsZeroWhenNothingIsHeld() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(userSecurityService.hasPin("@user:domain")).thenReturn(true);
        org.mockito.Mockito.when(userSecurityService.changePhonePinHoldRemainingSeconds("@user:domain"))
                .thenReturn(0L);

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.changePhoneCooldownRemainingSeconds").value(0));
    }

    @Test
    void pinStatusReportsTheRegisteredFactorsAndWhatAPhoneChangeAccepts() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(userSecurityService.hasPin("@user:domain")).thenReturn(true);
        org.mockito.Mockito.when(userSecurityService.changePhonePinHoldRemainingSeconds("@user:domain"))
                .thenReturn(0L);
        org.mockito.Mockito.when(passkeyService.isEnabled()).thenReturn(true);
        org.mockito.Mockito.when(passkeyService.hasPasskey("@user:domain")).thenReturn(true);

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                // Registered, which is server truth. There is no field for the client to say
                // the credential cannot be used on this device, and there must not be: anyone
                // holding a session could set it, so it would only ever be a way to be offered
                // something weaker.
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.passkeyRegistered").value(true))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.preferredFactor").value("PASSKEY"))
                // The precedence the client should offer comes from the same component the
                // step-up enforces, so the two cannot describe different rules.
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.phoneChangeStepUpFactors[0]").value("PASSKEY"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.phoneChangeStepUpFactors[1]").value("PIN"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.phoneChangeStepUpFactors.length()").value(2));
    }

    @Test
    void pinStatusReportsThePinAsPreferredForAnAccountWithNoPasskey() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(userSecurityService.hasPin("@user:domain")).thenReturn(true);
        org.mockito.Mockito.when(userSecurityService.changePhonePinHoldRemainingSeconds("@user:domain"))
                .thenReturn(0L);
        org.mockito.Mockito.when(passkeyService.isEnabled()).thenReturn(true);
        org.mockito.Mockito.when(passkeyService.hasPasskey("@user:domain")).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.passkeyRegistered").value(false))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.preferredFactor").value("PIN"))
                // The accepted set does not shrink to what this account holds. A client that
                // registers a passkey later does not need a different answer, and more to the
                // point, narrowing it per account is how the set collapses onto the one factor
                // that has become unusable.
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.phoneChangeStepUpFactors.length()").value(2));
    }

    @Test
    void requestingAPinResetIsAcceptedForAnAccountThatAlsoHoldsAPasskey() throws Exception {
        PinResetRequest request = new PinResetRequest();
        request.setUserId("@user:domain");
        request.setPhone("+12025550123");
        org.mockito.Mockito.when(passkeyService.isEnabled()).thenReturn(true);
        org.mockito.Mockito.when(passkeyService.hasPasskey("@user:domain")).thenReturn(true);

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/reset")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isAccepted());

        // Recovery is NOT gated on holding a stronger factor. Gating it would mean an account
        // whose passkey broke has no login and no recovery, and nothing in this service can
        // remove or replace a registered credential. The cross-factor view is spent on making
        // the event findable, not on refusing it.
        verify(userSecurityService).requestPinReset("@user:domain", "+12025550123", "127.0.0.1");
    }

    @Test
    void passkeyStepUpOptionsMintACeremonyForTheAuthenticatedAccount() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(passkeyService.startStepUpAssertion(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.eq("@user:domain")))
                .thenReturn(new ObjectMapper().createObjectNode().put("challenge", "abc"));

        mockMvc.perform(MockMvcRequestBuilders.post("/security/passkey/stepup/options")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.stepUpId")
                        .isNotEmpty())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.publicKey.challenge").value("abc"));

        // The ceremony is pinned to the caller, never to a user id taken from the request.
        org.mockito.ArgumentCaptor<String> stepUpId = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(passkeyService).startStepUpAssertion(stepUpId.capture(), org.mockito.ArgumentMatchers.eq("@user:domain"));
        org.junit.jupiter.api.Assertions.assertFalse(stepUpId.getValue().isBlank());
    }

    @Test
    void startPasskeyEnrollmentRefusesAnAccountWithoutAPerAccountLocalpart() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("ga1abc:x");
        org.mockito.Mockito.when(directoryService.findByUserId("ga1abc:x")).thenReturn(java.util.List.of());

        mockMvc.perform(MockMvcRequestBuilders.post("/security/passkey/enroll/start")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                        .isInternalServerError())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                        .value("account_identity_inconsistent"));

        verify(loginSessionService, org.mockito.Mockito.never())
                .create(org.mockito.ArgumentMatchers.any(LoginSession.class));
    }
}
