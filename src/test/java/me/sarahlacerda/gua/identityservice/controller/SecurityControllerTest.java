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
                new AuthFactorPolicy(userSecurityService, passkeyService),
                new AccountLocalpartResolver(directoryService), pinChangeService, accountRecoveryService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new RestExceptionHandler())
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

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
        org.junit.jupiter.api.Assertions.assertEquals(LoginSession.Phase.ENROLL_STEP_UP, created.getPhase());
        org.junit.jupiter.api.Assertions.assertEquals(LoginSession.EnrollTarget.PIN, created.getEnrollTarget());
        org.junit.jupiter.api.Assertions.assertNull(created.getEnrollStepUpFactor());
        org.junit.jupiter.api.Assertions.assertEquals("@alice:dev.local", created.getUserId());
        org.junit.jupiter.api.Assertions.assertEquals("@alice:dev.local", created.getReauthUserId());
        org.junit.jupiter.api.Assertions.assertTrue(created.isEnroll());
    }

    @Test
    void theEnrollmentRedirectComesFromTheClientBehindTheToken() throws Exception {
        OidcProperties.ClientRegistration qaBuild = new OidcProperties.ClientRegistration();
        qaBuild.setClientId("gua-ios-dev");
        qaBuild.setRedirectUris(java.util.List.of("global.gua.dev:/oidc"));
        oidcProperties.setClients(java.util.List.of(qaBuild));
        org.mockito.Mockito.when(authenticatedUserAccessor.currentClientId())
                .thenReturn(java.util.Optional.of("gua-ios-dev"));
        stubEnrollmentSessionFor("@alice:dev.local");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        org.junit.jupiter.api.Assertions.assertEquals("global.gua.dev:/oidc", createdSession().getRedirectUri());
    }

    @Test
    void theEnrollmentRedirectFallsBackToTheConfiguredValue() throws Exception {
        OidcProperties.ClientRegistration noRedirects = new OidcProperties.ClientRegistration();
        noRedirects.setClientId("gua-ios");
        noRedirects.setRedirectUris(java.util.List.of());
        OidcProperties.ClientRegistration webOnly = new OidcProperties.ClientRegistration();
        webOnly.setClientId("mas");
        webOnly.setRedirectUris(java.util.List.of("https://auth.example.com/upstream/callback"));
        oidcProperties.setClients(java.util.List.of(noRedirects, webOnly));
        loginProperties.getEnroll().setRedirectUri("global.gua:/oidc");

        for (java.util.Optional<String> client : java.util.List.of(
                java.util.Optional.<String>empty(), java.util.Optional.of("gua-ios"),
                java.util.Optional.of("mas"))) {
            org.mockito.Mockito.reset(loginSessionService);
            org.mockito.Mockito.when(authenticatedUserAccessor.currentClientId()).thenReturn(client);
            stubEnrollmentSessionFor("@alice:dev.local");

            mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                    .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

            org.junit.jupiter.api.Assertions.assertEquals("global.gua:/oidc", createdSession().getRedirectUri());
        }
    }

    private void stubEnrollmentSessionFor(String userId) {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn(userId);
        org.mockito.Mockito.when(userSecurityService.hasPin(userId)).thenReturn(false);
        org.mockito.Mockito.when(directoryService.findByUserId(userId))
                .thenReturn(java.util.List.of(DirectoryEntry.builder().userId(userId).displayName("Alice").build()));
        org.mockito.Mockito.when(loginSessionService.create(org.mockito.ArgumentMatchers.any(LoginSession.class)))
                .thenReturn("sess-1");
        org.mockito.Mockito.when(loginSessionService.newToken()).thenReturn("csrf-1");
        org.mockito.Mockito.when(loginSessionService.createEnrollToken(
                org.mockito.ArgumentMatchers.eq("sess-1"), org.mockito.ArgumentMatchers.any()))
                .thenReturn("tok-1");
    }

    private LoginSession createdSession() {
        org.mockito.ArgumentCaptor<LoginSession> captor = org.mockito.ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).create(captor.capture());
        return captor.getValue();
    }

    @Test
    void theCallerMayNameARedirectTheDeploymentAllows() throws Exception {
        loginProperties.getEnroll().setRedirectUri("global.gua:/oidc");
        loginProperties.getEnroll().setRedirectUris(java.util.List.of(
                "global.gua:/oidc", "global.gua.dev:/oidc", "global.gua.debug:/oidc"));

        for (String path : java.util.List.of("/security/pin/enroll/start", "/security/passkey/enroll/start")) {
            org.mockito.Mockito.reset(loginSessionService);
            stubEnrollmentSessionFor("@alice:dev.local");

            mockMvc.perform(MockMvcRequestBuilders.post(path)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"redirectUri\":\"global.gua.debug:/oidc\"}"))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

            org.junit.jupiter.api.Assertions.assertEquals("global.gua.debug:/oidc",
                    createdSession().getRedirectUri(), path);
        }
    }

    @Test
    void aRedirectOutsideTheAllowlistIsRefusedAndNoSessionIsCreated() throws Exception {
        loginProperties.getEnroll().setRedirectUri("global.gua:/oidc");
        loginProperties.getEnroll().setRedirectUris(java.util.List.of("global.gua:/oidc", "global.gua.dev:/oidc"));
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");

        for (String path : java.util.List.of("/security/pin/enroll/start", "/security/passkey/enroll/start")) {
            mockMvc.perform(MockMvcRequestBuilders.post(path)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"redirectUri\":\"https://attacker.example/steal\"}"))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                            .isBadRequest())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                            .value("invalid_redirect_uri"))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.message")
                            .value(org.hamcrest.Matchers.not(
                                    org.hamcrest.Matchers.containsString("attacker.example"))));
        }

        verify(loginSessionService, org.mockito.Mockito.never())
                .create(org.mockito.ArgumentMatchers.any(LoginSession.class));
    }

    @Test
    void aRedirectThatOnlyLooksLikeAnAllowedOneIsRefused() throws Exception {
        loginProperties.getEnroll().setRedirectUris(java.util.List.of("global.gua.dev:/oidc"));
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");

        for (String named : java.util.List.of("global.gua.dev:/oidc/../evil", "global.gua.dev.evil:/oidc",
                "global.gua.dev:/oidcx")) {
            mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(java.util.Map.of("redirectUri", named))))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                            .isBadRequest())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                            .value("invalid_redirect_uri"));
        }

        verify(loginSessionService, org.mockito.Mockito.never())
                .create(org.mockito.ArgumentMatchers.any(LoginSession.class));
    }

    @Test
    void theAllowlistIsTheSingleConfiguredRedirectUntilTheDeploymentNamesMore() throws Exception {
        loginProperties.getEnroll().setRedirectUri("global.gua:/oidc");
        org.junit.jupiter.api.Assertions.assertEquals(java.util.List.of("global.gua:/oidc"),
                loginProperties.getEnroll().allowedRedirectUris());
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"redirectUri\":\"global.gua.dev:/oidc\"}"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isBadRequest())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                        .value("invalid_redirect_uri"));

        stubEnrollmentSessionFor("@alice:dev.local");
        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"redirectUri\":\"global.gua:/oidc\"}"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        org.junit.jupiter.api.Assertions.assertEquals("global.gua:/oidc", createdSession().getRedirectUri());
    }

    @Test
    void anAllowedNameBeatsTheClientRegistration() throws Exception {
        OidcProperties.ClientRegistration storeBuild = new OidcProperties.ClientRegistration();
        storeBuild.setClientId("gua-ios");
        storeBuild.setRedirectUris(java.util.List.of("global.gua:/oidc"));
        oidcProperties.setClients(java.util.List.of(storeBuild));
        loginProperties.getEnroll().setRedirectUris(java.util.List.of("global.gua:/oidc", "global.gua.dev:/oidc"));
        stubEnrollmentSessionFor("@alice:dev.local");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"redirectUri\":\"global.gua.dev:/oidc\"}"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        org.junit.jupiter.api.Assertions.assertEquals("global.gua.dev:/oidc", createdSession().getRedirectUri());
        org.mockito.Mockito.verify(authenticatedUserAccessor, org.mockito.Mockito.never()).currentClientId();
    }

    @Test
    void anAbsentOrBlankRedirectLeavesTheDeploymentsOwnResolutionAlone() throws Exception {
        loginProperties.getEnroll().setRedirectUri("global.gua:/oidc");
        loginProperties.getEnroll().setRedirectUris(java.util.List.of("global.gua.dev:/oidc"));

        for (String body : java.util.Arrays.asList(null, "{}", "{\"redirectUri\":null}",
                "{\"redirectUri\":\"   \"}")) {
            org.mockito.Mockito.reset(loginSessionService);
            stubEnrollmentSessionFor("@alice:dev.local");

            org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder post = MockMvcRequestBuilders
                    .post("/security/pin/enroll/start")
                    .contentType(MediaType.APPLICATION_JSON);
            if (body != null) {
                post = post.content(body);
            }
            mockMvc.perform(post)
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

            org.junit.jupiter.api.Assertions.assertEquals("global.gua:/oidc", createdSession().getRedirectUri(),
                    String.valueOf(body));
        }
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
    void enrollmentIsRefusedWhenNoProofCanRunOnThisDeployment() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");
        org.mockito.Mockito.when(passkeyService.isEnabled()).thenReturn(false);
        org.mockito.Mockito.when(passkeyService.hasPasskey("@alice:dev.local")).thenReturn(true);

        for (String path : java.util.List.of("/security/pin/enroll/start", "/security/passkey/enroll/start")) {
            mockMvc.perform(MockMvcRequestBuilders.post(path)
                    .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isConflict())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                            .value("step_up_unavailable"));
        }

        verify(loginSessionService, org.mockito.Mockito.never())
                .create(org.mockito.ArgumentMatchers.any(LoginSession.class));
    }

    @Test
    void aPasskeyHolderMayStillAddAPinWhereThePasskeyCanBeAsserted() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@alice:dev.local");
        org.mockito.Mockito.when(passkeyService.isEnabled()).thenReturn(true);
        org.mockito.Mockito.when(passkeyService.hasPasskey("@alice:dev.local")).thenReturn(true);
        org.mockito.Mockito.when(directoryService.findByUserId("@alice:dev.local"))
                .thenReturn(java.util.List.of());
        org.mockito.Mockito.when(loginSessionService.create(org.mockito.ArgumentMatchers.any(LoginSession.class)))
                .thenReturn("sess-1");
        org.mockito.Mockito.when(loginSessionService.newToken()).thenReturn("csrf-1");
        org.mockito.Mockito.when(loginSessionService.createEnrollToken(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any())).thenReturn("tok-1");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/enroll/start")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        verify(loginSessionService).create(org.mockito.ArgumentMatchers.any(LoginSession.class));
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
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.passkeyRegistered").value(true))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.preferredFactor").value("PASSKEY"))
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
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.phoneChangeStepUpFactors.length()").value(2));
    }

    @Test
    void theRetiredPinResetEndpointsAnswerGoneAndTouchNothing() throws Exception {
        for (String path : new String[] { "/security/pin/reset", "/security/pin/reset/complete" }) {
            mockMvc.perform(MockMvcRequestBuilders.post(path)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"userId\":\"@user:domain\",\"phone\":\"+12025550123\",\"code\":\"876543\",\"newPin\":\"284917\"}"))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isGone())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                            .value("endpoint_retired"));
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

        mockMvc.perform(MockMvcRequestBuilders.post("/security/recovery/cancel"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isNoContent());
    }

    @Test
    void pinStatusReportsALiveRecoverySoEverySignedInAppCanShowTheBanner() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(accountRecoveryService.pendingFor("@user:domain")).thenReturn(java.util.Optional.of(
                new AccountRecoveryState(AccountRecoveryState.Status.PENDING, null, 1_760_000_000L, 1_760_604_800L,
                        604_800L, 604_800L)));

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
    void pinStatusReportsTheConfiguredRecoveryWaitsWithNoLiveEpisode() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        properties.getSecurity().setAccountRecoveryDormancy(java.time.Duration.ofMinutes(2));
        properties.getSecurity().setAccountRecoveryWait(java.time.Duration.ofMinutes(3));

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryPending").value(false))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryDormancySeconds").value(120))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accountRecoveryWaitSeconds").value(180));
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
