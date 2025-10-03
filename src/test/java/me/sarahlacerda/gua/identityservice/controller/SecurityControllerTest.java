package me.sarahlacerda.gua.identityservice.controller;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;

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

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        SecurityController controller = new SecurityController(userSecurityService, authenticatedUserAccessor);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
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
}
