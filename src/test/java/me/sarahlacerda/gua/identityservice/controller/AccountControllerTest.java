package me.sarahlacerda.gua.identityservice.controller;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
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
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.controller.dto.PhoneChangeCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PhoneChangeStartRequest;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneChangeChallengeException;
import me.sarahlacerda.gua.identityservice.exception.PhoneChangeCooldownException;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.security.AccountReauthService;
import me.sarahlacerda.gua.identityservice.service.security.PhoneChangeService;
import me.sarahlacerda.gua.identityservice.service.security.ReauthOperation;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;

@ExtendWith(MockitoExtension.class)
class AccountControllerTest {

    private static final String USER = "@alice:gua.global";

    @Mock
    private AccountReauthService reauthService;
    @Mock
    private AuthenticatedUserAccessor authenticatedUserAccessor;
    @Mock
    private MatrixAdminClient matrixAdminClient;
    @Mock
    private TokenRevocationService tokenRevocationService;
    @Mock
    private DirectoryService directoryService;
    @Mock
    private PhoneChangeService phoneChangeService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        AccountController controller = new AccountController(reauthService, authenticatedUserAccessor, matrixAdminClient,
                tokenRevocationService, directoryService, phoneChangeService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new RestExceptionHandler())
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    @Test
    void startPhoneChangeDelegatesToServiceWithReauthTokenAndNewPhone() throws Exception {
        when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn(USER);
        when(phoneChangeService.startPhoneNumberChange(eq(USER), eq("reauth-tok"), eq("+14155550123"), eq("123456"),
                any(), any(), any(), any()))
                .thenReturn(new PhoneChangeService.PhoneChangeStart("chal-1", 300L));

        PhoneChangeStartRequest request = new PhoneChangeStartRequest();
        request.setReauthToken("reauth-tok");
        request.setNewPhone("+14155550123");
        request.setPin("123456");

        mockMvc.perform(MockMvcRequestBuilders.post("/account/phone/change/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.challengeId", is("chal-1")))
                .andExpect(MockMvcResultMatchers.jsonPath("$.otpExpiresInSeconds", is(300)));

        verify(phoneChangeService).startPhoneNumberChange(eq(USER), eq("reauth-tok"), eq("+14155550123"), eq("123456"),
                any(), any(), any(), any());
    }

    @Test
    void startPhoneChangeRejectsBlankReauthToken() throws Exception {
        PhoneChangeStartRequest request = new PhoneChangeStartRequest();
        request.setReauthToken("");
        request.setNewPhone("+14155550123");

        mockMvc.perform(MockMvcRequestBuilders.post("/account/phone/change/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest());
    }

    @Test
    void completePhoneChangeReturns204() throws Exception {
        when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn(USER);

        PhoneChangeCompleteRequest request = new PhoneChangeCompleteRequest();
        request.setChallengeId("chal-1");
        request.setCode("654321");

        mockMvc.perform(MockMvcRequestBuilders.post("/account/phone/change/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        verify(phoneChangeService).completePhoneNumberChange(eq(USER), eq("chal-1"), eq("654321"), any());
    }

    @Test
    void completeMapsInvalidChallengeTo401() throws Exception {
        when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn(USER);
        doThrow(new InvalidPhoneChangeChallengeException("missing"))
                .when(phoneChangeService).completePhoneNumberChange(eq(USER), eq("chal-1"), eq("654321"), any());

        PhoneChangeCompleteRequest request = new PhoneChangeCompleteRequest();
        request.setChallengeId("chal-1");
        request.setCode("654321");

        mockMvc.perform(MockMvcRequestBuilders.post("/account/phone/change/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.jsonPath("$.code", is("phone_change_challenge_invalid")));
    }

    @Test
    void startMapsCooldownTo425WithRetryAfter() throws Exception {
        when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn(USER);
        doThrow(new PhoneChangeCooldownException("cooldown", 3600L))
                .when(phoneChangeService).startPhoneNumberChange(eq(USER), any(), any(), any(), any(), any(), any(),
                        any());

        PhoneChangeStartRequest request = new PhoneChangeStartRequest();
        request.setReauthToken("reauth-tok");
        request.setNewPhone("+14155550123");

        mockMvc.perform(MockMvcRequestBuilders.post("/account/phone/change/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isTooEarly())
                .andExpect(MockMvcResultMatchers.header().string("Retry-After", "3600"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.code", is("phone_change_cooldown")));
    }

    @Test
    void deactivatePassesDeactivateScopedReauth() throws Exception {
        when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn(USER);

        String body = "{\"reauthToken\":\"tok\",\"eraseData\":false}";

        mockMvc.perform(MockMvcRequestBuilders.post("/account/deactivate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        verify(reauthService).requireValidReauth(USER, "tok", ReauthOperation.DEACTIVATE);
    }
}
