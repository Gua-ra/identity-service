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
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeStartRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinUpdateRequest;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class SecurityControllerTest {

    @Mock
    private UserSecurityService userSecurityService;

    @Mock
    private AuthenticatedUserAccessor authenticatedUserAccessor;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;
    private IdentityServiceProperties properties;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        properties = new IdentityServiceProperties();
        SecurityController controller = new SecurityController(userSecurityService, authenticatedUserAccessor,
                properties);
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
}
