package me.sarahlacerda.gua.identityservice.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationRequest;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(OidcAuthorizationController.class)
@AutoConfigureMockMvc(addFilters = false)
class OidcAuthorizationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private OidcAuthorizationService authorizationService;

    @MockBean
    private OidcTokenService tokenService;

    @MockBean
    private EndpointRateLimiter endpointRateLimiter;

    @Test
    void authorizeIssuesCodeAndRedirects() throws Exception {
        OidcAuthorization authorization = new OidcAuthorization(
            "user-123",
            "+15551234567",
            "Alice",
            Set.of("openid", "profile"),
            "mas"
        );
        when(authorizationService.issueAuthorizationCode(any())).thenReturn(
            new OidcAuthorizationCode("auth-code", authorization, "https://client.example.com/callback")
        );

        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "mas")
                .param("redirect_uri", "https://client.example.com/callback")
                .param("scope", "openid profile")
                .param("phone_number", "+15551234567")
                .param("otp_code", "123456")
                .param("display_name", "Alice")
                .param("state", "abc"))
            .andExpect(status().isFound())
            .andExpect(header().string("Location", "https://client.example.com/callback?code=auth-code&state=abc"));

        ArgumentCaptor<OidcAuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(OidcAuthorizationRequest.class);
        verify(authorizationService).issueAuthorizationCode(requestCaptor.capture());
        OidcAuthorizationRequest captured = requestCaptor.getValue();
        assertThat(captured.clientId()).isEqualTo("mas");
        assertThat(captured.redirectUri()).isEqualTo("https://client.example.com/callback");
        assertThat(captured.scope()).containsExactlyInAnyOrder("openid", "profile");
        assertThat(captured.phoneNumber()).isEqualTo("+15551234567");
        assertThat(captured.otpCode()).isEqualTo("123456");
        assertThat(captured.displayName()).isEqualTo("Alice");
    }

    @Test
    void authorizeRejectsNonCodeResponseType() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "token")
                .param("client_id", "mas")
                .param("redirect_uri", "https://client.example.com/callback")
                .param("phone_number", "+15551234567")
                .param("otp_code", "123456"))
            .andExpect(status().isBadRequest());

        verifyNoInteractions(authorizationService);
    }

    @Test
    void tokenExchangesAuthorizationCode() throws Exception {
        OidcAuthorization authorization = new OidcAuthorization(
            "user-123",
            "+15551234567",
            "Alice",
            Set.of("openid"),
            "mas"
        );
        when(authorizationService.consumeAuthorizationCode("auth-code"))
            .thenReturn(Optional.of(new OidcAuthorizationCode("auth-code", authorization, "https://client.example.com/callback")));
        when(tokenService.issueTokens(authorization)).thenReturn(
            new OidcTokenResponse("access-token", 600, "openid", "Bearer", "id-token")
        );

        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "auth-code")
                .param("redirect_uri", "https://client.example.com/callback")
                .param("client_id", "mas"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").value("access-token"))
            .andExpect(jsonPath("$.expires_in").value(600))
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andExpect(jsonPath("$.id_token").value("id-token"));

        verify(authorizationService).consumeAuthorizationCode("auth-code");
        verify(tokenService).issueTokens(authorization);
    }

    @Test
    void tokenRejectsWhenGrantTypeIsNotAuthorizationCode() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "client_credentials")
                .param("code", "auth-code")
                .param("redirect_uri", "https://client.example.com/callback")
                .param("client_id", "mas"))
            .andExpect(status().isBadRequest());

        verifyNoInteractions(authorizationService);
        verifyNoInteractions(tokenService);
    }

    @Test
    void tokenRejectsWhenRedirectUriDoesNotMatch() throws Exception {
        OidcAuthorization authorization = new OidcAuthorization(
            "user-123",
            "+15551234567",
            null,
            Set.of("openid"),
            "mas"
        );
        when(authorizationService.consumeAuthorizationCode("auth-code"))
            .thenReturn(Optional.of(new OidcAuthorizationCode("auth-code", authorization, "https://client.example.com/other")));

        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "auth-code")
                .param("redirect_uri", "https://client.example.com/callback")
                .param("client_id", "mas"))
            .andExpect(status().isBadRequest());

        verify(authorizationService).consumeAuthorizationCode("auth-code");
        verify(tokenService, never()).issueTokens(any());
    }
}
