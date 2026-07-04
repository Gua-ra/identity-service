package me.sarahlacerda.gua.identityservice.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.controller.oidc.OidcAuthorizationController;
import me.sarahlacerda.gua.identityservice.exception.OidcClientAuthenticationException;
import me.sarahlacerda.gua.identityservice.exception.OidcInvalidRequestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationRequest;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService.RegisteredClient;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(OidcAuthorizationController.class)
@AutoConfigureMockMvc(addFilters = false)
class OidcAuthorizationControllerTest {

    private static final String CALLBACK = "https://client.example.com/callback";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private OidcAuthorizationService authorizationService;

    @MockitoBean
    private OidcTokenService tokenService;

    @MockitoBean
    private OidcClientService clientService;

    @MockitoBean
    private LoginSessionService loginSessionService;

    @MockitoBean
    private LoginFlowProperties loginFlowProperties;

    @MockitoBean
    private EndpointRateLimiter endpointRateLimiter;

    private RegisteredClient confidentialClient;
    private RegisteredClient publicClient;

    @BeforeEach
    void setUp() {
        confidentialClient = new RegisteredClient("mas", "$2a$10$abc", false,
                List.of(CALLBACK), Set.of("openid", "profile", "phone"), false);
        publicClient = new RegisteredClient("gua-ios", null, true,
                List.of("global.gua:/oidc"), Set.of("openid", "profile", "phone"), true);
        when(clientService.requireClient("mas")).thenReturn(confidentialClient);
        when(clientService.requireClient("gua-ios")).thenReturn(publicClient);
    }

    @Test
    void authorizeIssuesCodeAndRedirects() throws Exception {
        OidcAuthorization authorization = new OidcAuthorization(
                "user-123", "+15551234567", "Alice", Set.of("openid", "profile"), "mas");
        when(authorizationService.issueAuthorizationCode(any())).thenReturn(
                new OidcAuthorizationCode("auth-code", authorization, CALLBACK));

        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "mas")
                .param("redirect_uri", CALLBACK)
                .param("scope", "openid profile")
                .param("phone_number", "+15551234567")
                .param("otp_code", "123456")
                .param("display_name", "Alice")
                .param("state", "abc"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", CALLBACK + "?code=auth-code&state=abc"));

        verify(clientService).requireClient("mas");
        verify(clientService).validateRedirectUri(confidentialClient, CALLBACK);
        verify(clientService).validateScope(eq(confidentialClient), any());
        verify(clientService).validateChallenge(confidentialClient, null, null);

        ArgumentCaptor<OidcAuthorizationRequest> captor = ArgumentCaptor.forClass(OidcAuthorizationRequest.class);
        verify(authorizationService).issueAuthorizationCode(captor.capture());
        assertThat(captor.getValue().codeChallenge()).isNull();
    }

    @Test
    void authorizeWithPkcePropagatesChallenge() throws Exception {
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        when(authorizationService.issueAuthorizationCode(any())).thenReturn(
                new OidcAuthorizationCode(
                        "code-pkce",
                        new OidcAuthorization("user-x", "+15550009999", null, Set.of("openid"), "gua-ios"),
                        "global.gua:/oidc",
                        Optional.of(challenge)));

        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "gua-ios")
                .param("redirect_uri", "global.gua:/oidc")
                .param("phone_number", "+15550009999")
                .param("otp_code", "654321")
                .param("code_challenge", challenge)
                .param("code_challenge_method", "S256"))
                .andExpect(status().isFound());

        verify(clientService).validateChallenge(publicClient, challenge, "S256");
        ArgumentCaptor<OidcAuthorizationRequest> captor = ArgumentCaptor.forClass(OidcAuthorizationRequest.class);
        verify(authorizationService).issueAuthorizationCode(captor.capture());
        assertThat(captor.getValue().codeChallenge()).isEqualTo(challenge);
    }

    @Test
    void authorizeInteractiveFlowStoresDownstreamClientOnSession() throws Exception {
        when(loginFlowProperties.getCookieName()).thenReturn("gua_login");
        when(loginFlowProperties.isCookieSecure()).thenReturn(true);
        when(loginFlowProperties.getSessionTtl()).thenReturn(java.time.Duration.ofMinutes(10));
        when(loginFlowProperties.getUiUrl()).thenReturn("/signin");
        when(loginSessionService.newToken()).thenReturn("csrf-1");
        when(loginSessionService.create(any())).thenReturn("sid-1");

        // Interactive flow: omit phone_number/otp_code so the session-parking branch runs.
        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "mas")
                .param("redirect_uri", CALLBACK)
                .param("scope", "openid profile")
                .param("gua_downstream", "web"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "/signin"));

        ArgumentCaptor<me.sarahlacerda.gua.identityservice.service.oidc.LoginSession> captor =
                ArgumentCaptor.forClass(me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.class);
        verify(loginSessionService).create(captor.capture());
        assertThat(captor.getValue().getDownstreamClient()).isEqualTo("web");

        verifyNoInteractions(authorizationService);
    }

    @Test
    void authorizeInteractiveFlowLeavesDownstreamClientNullWhenSignalAbsent() throws Exception {
        when(loginFlowProperties.getCookieName()).thenReturn("gua_login");
        when(loginFlowProperties.isCookieSecure()).thenReturn(true);
        when(loginFlowProperties.getSessionTtl()).thenReturn(java.time.Duration.ofMinutes(10));
        when(loginFlowProperties.getUiUrl()).thenReturn("/signin");
        when(loginSessionService.newToken()).thenReturn("csrf-1");
        when(loginSessionService.create(any())).thenReturn("sid-1");

        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "mas")
                .param("redirect_uri", CALLBACK)
                .param("scope", "openid profile"))
                .andExpect(status().isFound());

        ArgumentCaptor<me.sarahlacerda.gua.identityservice.service.oidc.LoginSession> captor =
                ArgumentCaptor.forClass(me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.class);
        verify(loginSessionService).create(captor.capture());
        assertThat(captor.getValue().getDownstreamClient()).isNull();
    }

    @Test
    void authorizeRejectsNonCodeResponseType() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "token")
                .param("client_id", "mas")
                .param("redirect_uri", CALLBACK)
                .param("phone_number", "+15551234567")
                .param("otp_code", "123456"))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authorizationService);
    }

    @Test
    void authorizeRejectsUnknownClient() throws Exception {
        when(clientService.requireClient("ghost"))
                .thenThrow(new OidcInvalidRequestException("invalid_client", "Unknown client_id"));

        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "ghost")
                .param("redirect_uri", CALLBACK)
                .param("phone_number", "+15551234567")
                .param("otp_code", "123456"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_client"));

        verifyNoInteractions(authorizationService);
    }

    @Test
    void tokenExchangesAuthorizationCodeWithClientSecret() throws Exception {
        OidcAuthorization authorization = new OidcAuthorization(
                "user-123", "+15551234567", "Alice", Set.of("openid"), "mas");
        when(authorizationService.consumeAuthorizationCode("auth-code"))
                .thenReturn(Optional.of(new OidcAuthorizationCode("auth-code", authorization, CALLBACK)));
        when(tokenService.issueTokens(authorization)).thenReturn(
                new OidcTokenResponse("access-token", 600, "openid", "Bearer", "id-token"));

        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "auth-code")
                .param("redirect_uri", CALLBACK)
                .param("client_id", "mas")
                .param("client_secret", "shh"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("access-token"))
                .andExpect(jsonPath("$.expires_in").value(600))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.id_token").value("id-token"));

        verify(clientService).authenticateClient(confidentialClient, "shh");
        verify(clientService).verifyPkce(Optional.empty(), null);
        verify(authorizationService).consumeAuthorizationCode("auth-code");
        verify(tokenService).issueTokens(authorization);
    }

    @Test
    void tokenAcceptsHttpBasicClientAuthentication() throws Exception {
        OidcAuthorization authorization = new OidcAuthorization(
                "user-123", "+15551234567", null, Set.of("openid"), "mas");
        when(authorizationService.consumeAuthorizationCode("auth-code"))
                .thenReturn(Optional.of(new OidcAuthorizationCode("auth-code", authorization, CALLBACK)));
        when(tokenService.issueTokens(authorization)).thenReturn(
                new OidcTokenResponse("at", 600, "openid", "Bearer", "it"));

        String basic = java.util.Base64.getEncoder().encodeToString("mas:shh".getBytes());
        mockMvc.perform(post("/oauth2/token")
                .header("Authorization", "Basic " + basic)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "auth-code")
                .param("redirect_uri", CALLBACK))
                .andExpect(status().isOk());

        verify(clientService).requireClient("mas");
        verify(clientService).authenticateClient(confidentialClient, "shh");
    }

    @Test
    void tokenRejectsInvalidClientSecret() throws Exception {
        doThrow(new OidcClientAuthenticationException("Invalid client_secret"))
                .when(clientService).authenticateClient(any(), anyString());

        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "auth-code")
                .param("redirect_uri", CALLBACK)
                .param("client_id", "mas")
                .param("client_secret", "wrong"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("invalid_client"));

        verifyNoInteractions(authorizationService);
        verifyNoInteractions(tokenService);
    }

    @Test
    void tokenRejectsPkceMismatch() throws Exception {
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        OidcAuthorization authorization = new OidcAuthorization(
                "user-x", "+15550009999", null, Set.of("openid"), "gua-ios");
        when(authorizationService.consumeAuthorizationCode("auth-code"))
                .thenReturn(Optional.of(new OidcAuthorizationCode("auth-code", authorization,
                        "global.gua:/oidc", Optional.of(challenge))));
        doThrow(new OidcInvalidRequestException("invalid_grant", "code_verifier does not match"))
                .when(clientService).verifyPkce(Optional.of(challenge), "wrong-verifier");

        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "auth-code")
                .param("redirect_uri", "global.gua:/oidc")
                .param("client_id", "gua-ios")
                .param("code_verifier", "wrong-verifier"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_grant"));

        verify(tokenService, never()).issueTokens(any());
    }

    @Test
    void tokenRejectsWhenGrantTypeIsNotAuthorizationCode() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "client_credentials")
                .param("code", "auth-code")
                .param("redirect_uri", CALLBACK)
                .param("client_id", "mas"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("unsupported_grant_type"));

        verifyNoInteractions(authorizationService);
        verifyNoInteractions(tokenService);
    }

    @Test
    void tokenRejectsWhenRedirectUriDoesNotMatch() throws Exception {
        OidcAuthorization authorization = new OidcAuthorization(
                "user-123", "+15551234567", null, Set.of("openid"), "mas");
        when(authorizationService.consumeAuthorizationCode("auth-code"))
                .thenReturn(Optional.of(new OidcAuthorizationCode("auth-code", authorization, "https://other/cb")));

        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "auth-code")
                .param("redirect_uri", CALLBACK)
                .param("client_id", "mas")
                .param("client_secret", "shh"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_grant"));

        verify(tokenService, never()).issueTokens(any());
    }
}
