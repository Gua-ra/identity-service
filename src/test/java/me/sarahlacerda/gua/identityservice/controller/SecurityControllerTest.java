package me.sarahlacerda.gua.identityservice.controller;

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
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.AccountLocalpartResolver;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryService;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState;
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

    @Mock
    private AccountRecoveryService accountRecoveryService;

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
                new AccountLocalpartResolver(directoryService), pinChangeService, accountRecoveryService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new RestExceptionHandler())
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    /**
     * R2: a bearer session on its own never adds a durable factor. The endpoint stores nothing
     * and names the flow that does the work, so an older client is told where to go instead of
     * failing on a payload that was never going to be kept.
     */
    @Test
    void theBearerFirstPinIsRefusedAndNamesTheEnrollmentFlow() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"@user:domain\",\"newPin\":\"123456\"}"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                        .value("step_up_required"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.message")
                        .value(org.hamcrest.Matchers.containsString("/security/pin/enroll/start")));

        org.mockito.Mockito.verifyNoInteractions(userSecurityService);
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

    /** Whatever the body says, including an empty one: the answer is the same and nothing is read. */
    @Test
    void theBearerFirstPinIsRefusedWhateverTheBodySays() throws Exception {
        for (String body : java.util.List.of("{}", "{\"userId\":\"@user:domain\",\"currentPin\":\"123456\"}")) {
            mockMvc.perform(MockMvcRequestBuilders.post("/security/pin")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                            .value("step_up_required"));
        }

        org.mockito.Mockito.verifyNoInteractions(userSecurityService);
    }

    @Test
    void startPinEnrollmentReturnsAbsoluteEnrollUrlAndParksAtTheStepUp() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");
        org.mockito.Mockito.when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(false);
        org.mockito.Mockito.when(directoryService.findByUserId("@alice:dev.local"))
                .thenReturn(java.util.List.of(
                        DirectoryEntry.builder().userId("@alice:dev.local").displayName("Alice").build()));
        org.mockito.Mockito.when(loginSessionService.create(org.mockito.ArgumentMatchers.any(LoginSession.class)))
                .thenReturn("sess-1");
        org.mockito.Mockito.when(loginSessionService.newToken()).thenReturn("csrf-1");
        org.mockito.Mockito.when(loginSessionService.createEnrollToken(
                org.mockito.ArgumentMatchers.eq("sess-1"), org.mockito.ArgumentMatchers.any()))
                .thenReturn("tok-1");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.enrollUrl")
                        .value("https://auth.example.com/login/enroll/tok-1"));

        org.mockito.ArgumentCaptor<LoginSession> captor = org.mockito.ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).create(captor.capture());
        LoginSession created = captor.getValue();
        // Nothing can be stored from this session until it has been through the step-up.
        org.junit.jupiter.api.Assertions.assertEquals(LoginSession.Phase.ENROLL_STEP_UP, created.getPhase());
        org.junit.jupiter.api.Assertions.assertEquals(LoginSession.EnrollTarget.PIN, created.getEnrollTarget());
        org.junit.jupiter.api.Assertions.assertNull(created.getEnrollStepUpFactor());
        org.junit.jupiter.api.Assertions.assertEquals("@alice:dev.local", created.getUserId());
        org.junit.jupiter.api.Assertions.assertEquals("@alice:dev.local", created.getReauthUserId());
        org.junit.jupiter.api.Assertions.assertTrue(created.isEnroll());
    }

    @Test
    void startPinEnrollmentRefusesAnAccountThatAlreadyHasAPin() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");
        org.mockito.Mockito.when(userSecurityService.hasPin("@alice:dev.local")).thenReturn(true);

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isConflict())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                        .value("pin_already_set"));

        verify(loginSessionService, org.mockito.Mockito.never())
                .create(org.mockito.ArgumentMatchers.any(LoginSession.class));
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
                        .value("https://auth.example.com/login/enroll/tok-1"));
    }

    @Test
    void startPasskeyEnrollmentPinsSessionToAuthenticatedUserAtTheStepUp() throws Exception {
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
        org.junit.jupiter.api.Assertions.assertEquals(LoginSession.Phase.ENROLL_STEP_UP, created.getPhase());
        org.junit.jupiter.api.Assertions.assertEquals(LoginSession.EnrollTarget.PASSKEY, created.getEnrollTarget());
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

    /**
     * E3: the unauthenticated reset shared the recovery episode but not its rules. Both paths now
     * answer 410 whatever is sent, without reading a body and without touching any account.
     */
    @Test
    void theRetiredPinResetEndpointsAnswerGoneAndTouchNothing() throws Exception {
        for (String path : new String[] { "/security/pin/reset", "/security/pin/reset/complete" }) {
            mockMvc.perform(MockMvcRequestBuilders.post(path)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"userId\":\"@user:domain\",\"phone\":\"+12025550123\",\"code\":\"876543\",\"newPin\":\"284917\"}"))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isGone())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                            .value("endpoint_retired"));
            // No body at all is the same answer, not a validation error.
            mockMvc.perform(MockMvcRequestBuilders.post(path))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isGone());
        }

        org.mockito.Mockito.verifyNoInteractions(userSecurityService, accountRecoveryService, passkeyService,
                directoryService);
    }

    @Test
    void cancellingARecoveryDelegatesForTheAuthenticatedAccountAndAnswersNoContent() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(accountRecoveryService.cancel("@user:domain", "127.0.0.1")).thenReturn(true);

        mockMvc.perform(MockMvcRequestBuilders.post("/security/recovery/cancel"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isNoContent());

        verify(accountRecoveryService).cancel("@user:domain", "127.0.0.1");
    }

    @Test
    void cancellingWhenNoRecoveryIsLiveIsTheSameAnswer() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(accountRecoveryService.cancel("@user:domain", "127.0.0.1")).thenReturn(false);

        // 204 either way: the banner only needs to know nothing is live any more.
        mockMvc.perform(MockMvcRequestBuilders.post("/security/recovery/cancel"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isNoContent());
    }

    @Test
    void pinStatusReportsALiveRecoverySoEverySignedInAppCanShowTheBanner() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(accountRecoveryService.pendingFor("@user:domain")).thenReturn(java.util.Optional.of(
                new AccountRecoveryState(AccountRecoveryState.Status.PENDING, null, 1_760_000_000L, 1_760_604_800L)));

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryPending").value(true))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryCompletableAtEpochSeconds").value(1_760_000_000L))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryExpiresAtEpochSeconds").value(1_760_604_800L));
    }

    @Test
    void pinStatusReportsNoRecoveryWithNullTimes() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryPending").value(false))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryCompletableAtEpochSeconds").doesNotExist())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryExpiresAtEpochSeconds").doesNotExist());
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
