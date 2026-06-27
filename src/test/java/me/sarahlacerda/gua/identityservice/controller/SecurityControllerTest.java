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
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
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
    private me.sarahlacerda.gua.identityservice.service.security.ReauthTokenService reauthTokenService;

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
                properties, directoryService, loginSessionService, loginProperties, oidcProperties,
                reauthTokenService);
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
    void pinReauthValidatesPinAndIssuesReauthToken() throws Exception {
        me.sarahlacerda.gua.identityservice.controller.dto.PinReauthRequest request =
                new me.sarahlacerda.gua.identityservice.controller.dto.PinReauthRequest();
        request.setUserId("@user:domain");
        request.setPin("123456");

        doNothing().when(authenticatedUserAccessor).requireUserIdMatches("@user:domain");
        org.mockito.Mockito.when(reauthTokenService.issue("@user:domain")).thenReturn("reauth-tok");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/reauth")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.reauthToken")
                        .value("reauth-tok"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.expiresInSeconds").value(300));

        verify(userSecurityService).validatePinForReauthOrThrow("@user:domain", "123456");
    }

    @Test
    void pinReauthWithoutPinReturnsPinSetupRequired() throws Exception {
        me.sarahlacerda.gua.identityservice.controller.dto.PinReauthRequest request =
                new me.sarahlacerda.gua.identityservice.controller.dto.PinReauthRequest();
        request.setUserId("@user:domain");
        request.setPin("123456");

        doNothing().when(authenticatedUserAccessor).requireUserIdMatches("@user:domain");
        org.mockito.Mockito.doThrow(
                new me.sarahlacerda.gua.identityservice.exception.PinSetupRequiredException("PIN not set for user"))
                .when(userSecurityService).validatePinForReauthOrThrow("@user:domain", "123456");

        mockMvc.perform(MockMvcRequestBuilders.post("/security/pin/reauth")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isBadRequest())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code")
                        .value("pin_setup_required"));

        org.mockito.Mockito.verify(reauthTokenService, org.mockito.Mockito.never())
                .issue(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void pinStatusReturnsHasPinAndCooldownRemaining() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(userSecurityService.hasPin("@user:domain")).thenReturn(true);
        org.mockito.Mockito.when(userSecurityService.changePhoneCooldownRemainingSeconds("@user:domain"))
                .thenReturn(3600L);

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.hasPin")
                        .value(true))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.changePhoneCooldownRemainingSeconds").value(3600));
    }

    @Test
    void pinStatusReportsZeroCooldownWhenNoPin() throws Exception {
        org.mockito.Mockito.when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@user:domain");
        org.mockito.Mockito.when(userSecurityService.hasPin("@user:domain")).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders.get("/security/pin/status"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.hasPin")
                        .value(false))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.changePhoneCooldownRemainingSeconds").value(0));

        org.mockito.Mockito.verify(userSecurityService, org.mockito.Mockito.never())
                .changePhoneCooldownRemainingSeconds(org.mockito.ArgumentMatchers.anyString());
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
        org.mockito.Mockito.when(userSecurityService.startPinChange(
                org.mockito.ArgumentMatchers.eq("@user:domain"),
                org.mockito.ArgumentMatchers.eq("+12025550123"),
                org.mockito.ArgumentMatchers.eq("123456"),
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
}
