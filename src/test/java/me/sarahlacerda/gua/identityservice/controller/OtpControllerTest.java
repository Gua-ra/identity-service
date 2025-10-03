package me.sarahlacerda.gua.identityservice.controller;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

import me.sarahlacerda.gua.identityservice.controller.dto.OtpChangeNumberRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpSendRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyRequest.DeviceInfo;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyResponse;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.IdentityOrchestrationService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class OtpControllerTest {

    @Mock
    private IdentityOrchestrationService orchestrationService;

    @Mock
    private AuthenticatedUserAccessor authenticatedUserAccessor;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        OtpController controller = new OtpController(orchestrationService, authenticatedUserAccessor);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setMessageConverters(new MappingJackson2HttpMessageConverter())
            .build();
    }

    @Test
    void sendOtpDelegatesToService() throws Exception {
        OtpSendRequest request = new OtpSendRequest();
        request.setPhone("+12025550123");
        request.setLanguage("pt-BR");

        mockMvc.perform(MockMvcRequestBuilders.post("/otp/send")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isAccepted());

        verify(orchestrationService).sendOtp("+12025550123", "127.0.0.1", "pt-BR");
    }

    @Test
    void verifyOtpReturnsSession() throws Exception {
        OtpVerifyRequest request = new OtpVerifyRequest();
        request.setPhone("+12025550123");
        request.setCode("123456");
        DeviceInfo deviceInfo = new DeviceInfo();
        deviceInfo.setName("iPhone");
        deviceInfo.setPlatform("iOS");
        deviceInfo.setAppVersion("1.0");
        request.setDevice(deviceInfo);

        MatrixSession session = new MatrixSession("token", "@user:domain", "device", "https://matrix");
        when(orchestrationService.verifyOtpAndSignIn(eq("+12025550123"), eq("123456"), any(), any(), any(DeviceMetadata.class)))
            .thenReturn(session);

        mockMvc.perform(MockMvcRequestBuilders.post("/otp/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.accessToken", is("token")));
    }

    @Test
    void changeNumberRequiresMatchingUser() throws Exception {
        OtpChangeNumberRequest request = new OtpChangeNumberRequest();
        request.setUserId("@user:domain");
        request.setNewPhone("+19999999999");
        request.setCode("123456");
        request.setPin("999999");

        doNothing().when(authenticatedUserAccessor).requireUserIdMatches("@user:domain");

        mockMvc.perform(MockMvcRequestBuilders.post("/otp/change-number")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isNoContent());

        verify(orchestrationService).changePhoneNumber("@user:domain", "+19999999999", "123456", "999999");
    }
}
