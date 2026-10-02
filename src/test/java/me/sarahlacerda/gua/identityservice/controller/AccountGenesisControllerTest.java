package me.sarahlacerda.gua.identityservice.controller;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import me.sarahlacerda.gua.identityservice.account.genesis.InvalidGenesisException;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountGenesisRegisterResponse;
import me.sarahlacerda.gua.identityservice.exception.GenesisRegistrationException;
import me.sarahlacerda.gua.identityservice.service.account.AccountGenesisService;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The HTTP contract of {@code POST /account/genesis}. */
@WebMvcTest(AccountGenesisController.class)
@AutoConfigureMockMvc(addFilters = false)
class AccountGenesisControllerTest {

    private static final String BODY = """
            {"genesis":"R1VBRw","proof":"c2ln"}
            """;

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AccountGenesisService accountGenesisService;

    @MockitoBean
    private EndpointRateLimiter endpointRateLimiter;

    @Test
    void aRegisteredGenesisIsReturnedWithItsHandleAs201() throws Exception {
        when(accountGenesisService.register(anyString(), anyString())).thenReturn(
                new AccountGenesisRegisterResponse("ga1accountid", "the-handle", Instant.parse("2026-01-01T00:00:00Z")));

        mockMvc.perform(post("/account/genesis").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accountId").value("ga1accountid"))
                .andExpect(jsonPath("$.attachHandle").value("the-handle"))
                .andExpect(jsonPath("$.expiresAt").exists());
    }

    @Test
    void theEndpointAnswers503WhileTheFeatureIsOff() throws Exception {
        when(accountGenesisService.register(anyString(), anyString())).thenThrow(
                new GenesisRegistrationException(HttpStatus.SERVICE_UNAVAILABLE, "genesis_disabled", "off"));

        mockMvc.perform(post("/account/genesis").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("genesis_disabled"));
    }

    @Test
    void aMalformedGenesisIs400AndNamesTheRuleThatRefusedIt() throws Exception {
        when(accountGenesisService.register(anyString(), anyString()))
                .thenThrow(new InvalidGenesisException("wrong_length", "nope"));

        mockMvc.perform(post("/account/genesis").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_genesis"))
                .andExpect(jsonPath("$.message").value("Rejected by rule: wrong_length"));
    }

    @Test
    void aProofThatDoesNotVerifyIs400() throws Exception {
        when(accountGenesisService.register(anyString(), anyString())).thenThrow(
                new GenesisRegistrationException(HttpStatus.BAD_REQUEST, "invalid_genesis_proof", "nope"));

        mockMvc.perform(post("/account/genesis").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_genesis_proof"));
    }

    @Test
    void aGatedRecoveryFrameworkIs403() throws Exception {
        when(accountGenesisService.register(anyString(), anyString())).thenThrow(
                new GenesisRegistrationException(HttpStatus.FORBIDDEN, "genesis_issuance_not_permitted", "nope"));

        mockMvc.perform(post("/account/genesis").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("genesis_issuance_not_permitted"));
    }

    @Test
    void anAlreadyAttachedGenesisIs409() throws Exception {
        when(accountGenesisService.register(anyString(), anyString())).thenThrow(
                new GenesisRegistrationException(HttpStatus.CONFLICT, "genesis_already_attached", "nope"));

        mockMvc.perform(post("/account/genesis").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("genesis_already_attached"));
    }

    @Test
    void aBodyMissingEitherFieldIsRejectedBeforeTheServiceIsCalled() throws Exception {
        mockMvc.perform(post("/account/genesis").contentType(MediaType.APPLICATION_JSON)
                .content("{\"genesis\":\"R1VBRw\"}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/account/genesis").contentType(MediaType.APPLICATION_JSON)
                .content("{\"proof\":\"c2ln\"}"))
                .andExpect(status().isBadRequest());

        org.mockito.Mockito.verify(accountGenesisService, org.mockito.Mockito.never())
                .register(anyString(), anyString());
    }
}
