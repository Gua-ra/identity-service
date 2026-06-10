package me.sarahlacerda.gua.identityservice.controller;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.SignupCompleteRequest;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.service.IdentityOrchestrationService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;

@ExtendWith(MockitoExtension.class)
class SignupControllerTest {

    @Mock
    private IdentityOrchestrationService orchestrationService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        SignupController controller = new SignupController(orchestrationService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    @Test
    void completeSignupReturnsSession() throws Exception {
        SignupCompleteRequest request = new SignupCompleteRequest();
        request.setSignupToken("signup-abc");
        request.setUsername("alice");
        request.setDisplayName("Alice L.");
        OtpVerifyRequest.DeviceInfo deviceInfo = new OtpVerifyRequest.DeviceInfo();
        deviceInfo.setName("iPhone");
        deviceInfo.setPlatform("iOS");
        deviceInfo.setAppVersion("1.0");
        request.setDevice(deviceInfo);

        MatrixSession session = new MatrixSession("token", "@alice:gua.global", "DEV1", "https://matrix");
        when(orchestrationService.completeSignup(
                eq("signup-abc"), eq("alice"), eq("Alice L."), any(), any(DeviceMetadata.class))).thenReturn(session);

        mockMvc.perform(MockMvcRequestBuilders.post("/signup/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.accessToken",
                        is("token")))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.userId",
                        is("@alice:gua.global")));
    }

    @Test
    void completeSignupRejectsMissingFields() throws Exception {
        SignupCompleteRequest request = new SignupCompleteRequest();
        request.setSignupToken("signup-abc");
        request.setUsername("");
        request.setDisplayName("");

        mockMvc.perform(MockMvcRequestBuilders.post("/signup/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isBadRequest());
    }
}
