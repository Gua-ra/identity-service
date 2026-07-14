package me.sarahlacerda.gua.identityservice.controller;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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

import me.sarahlacerda.gua.identityservice.controller.dto.OtpSendRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyRequest.DeviceInfo;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyResponse;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.domain.VerifyOtpResult;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.IdentityOrchestrationService;
import me.sarahlacerda.gua.identityservice.service.RegistrationGuard;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.HttpStatus;

@ExtendWith(MockitoExtension.class)
class OtpControllerTest {

    @Mock
    private IdentityOrchestrationService orchestrationService;

    @Mock
    private AuthenticatedUserAccessor authenticatedUserAccessor;

    @Mock
    private RegistrationGuard registrationGuard;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        OtpController controller = new OtpController(orchestrationService, authenticatedUserAccessor,
                registrationGuard);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new RestExceptionHandler())
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
    void sendOtpBlockedWhenGateRejectsNumberBeforeDispatch() throws Exception {
        OtpSendRequest request = new OtpSendRequest();
        request.setPhone("+12025550123");

        org.mockito.Mockito.doThrow(new LoginFlowException(HttpStatus.FORBIDDEN, "registration_not_approved",
                "New account sign-ups are currently invite-only. This phone number is not on the list yet."))
                .when(registrationGuard).assertOtpAllowed("+12025550123");

        mockMvc.perform(MockMvcRequestBuilders.post("/otp/send")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code",
                        is("registration_not_approved")));

        verify(orchestrationService, org.mockito.Mockito.never()).sendOtp(any(), any(), any());
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
        when(orchestrationService.verifyOtpAndSignIn(eq("+12025550123"), eq("123456"), any(),
                any(DeviceMetadata.class)))
                .thenReturn(VerifyOtpResult.existingUser(session));

        mockMvc.perform(MockMvcRequestBuilders.post("/otp/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.accessToken",
                        is("token")))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.isNewUser",
                        is(false)));
    }

    @Test
    void verifyOtpReturnsSignupTokenForNewUser() throws Exception {
        OtpVerifyRequest request = new OtpVerifyRequest();
        request.setPhone("+12025550199");
        request.setCode("123456");

        when(orchestrationService.verifyOtpAndSignIn(eq("+12025550199"), eq("123456"), any(), any()))
                .thenReturn(VerifyOtpResult.newUser("signup-token-abc"));

        mockMvc.perform(MockMvcRequestBuilders.post("/otp/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.isNewUser",
                        is(true)))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.signupToken",
                        is("signup-token-abc")));
    }

}
