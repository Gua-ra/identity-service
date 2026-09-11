package me.sarahlacerda.gua.identityservice.controller;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.controller.oidc.OidcAuthorizationController;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The {@code gua:} login-hint grammar (ADM-008 decision 6, step 2).
 *
 * <p>The grammar is strict on purpose. An unparsable hint, an unknown or duplicated key and a malformed
 * {@code genesis} value are refused rather than ignored, because quietly dropping a handle is the silent
 * downgrade the decision forbids. It applies only to prefixed hints and only while the feature is on, so
 * the reserved value {@code passkey} and every other hint keep the behaviour they had before it existed.
 */
@WebMvcTest(OidcAuthorizationController.class)
@AutoConfigureMockMvc(addFilters = false)
class OidcAuthorizationGenesisHintTest {

    private static final String CALLBACK = "https://client.example.com/callback";
    private static final String HANDLE = "Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0";

    @Autowired
    private MockMvc mockMvc;

    /** The real bound properties bean the slice already provides; each test sets the flag it needs. */
    @Autowired
    private IdentityServiceProperties identityServiceProperties;

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

    @BeforeEach
    void setUp() {
        identityServiceProperties.getGenesis().setEnabled(true);
        when(loginFlowProperties.getCookieName()).thenReturn("gua_login");
        when(loginFlowProperties.getUiUrl()).thenReturn("/signin");
        when(loginFlowProperties.getSessionTtl()).thenReturn(Duration.ofMinutes(10));
        when(loginSessionService.create(any())).thenReturn("session-id");
        when(loginSessionService.newToken()).thenReturn("csrf-token");
    }

    private org.springframework.test.web.servlet.ResultActions authorize(String loginHint) throws Exception {
        var request = get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "mas")
                .param("redirect_uri", CALLBACK)
                .param("scope", "openid profile");
        if (loginHint != null) {
            request = request.param("login_hint", loginHint);
        }
        return mockMvc.perform(request);
    }

    private LoginSession parkedSession() {
        ArgumentCaptor<LoginSession> session = ArgumentCaptor.forClass(LoginSession.class);
        verify(loginSessionService).create(session.capture());
        return session.getValue();
    }

    @Test
    void aGuaHintCarriesThePhoneAndTheAttachHandleOntoTheSession() throws Exception {
        authorize("gua:phone=+15551234567;genesis=" + HANDLE).andExpect(status().isFound());

        LoginSession session = parkedSession();
        assertThat(session.getPhoneHint()).isEqualTo("+15551234567");
        assertThat(session.getGenesisAttachHandle()).isEqualTo(HANDLE);
        assertThat(session.getIntent()).isEqualTo(LoginSession.Intent.PHONE);
    }

    @Test
    void aGuaHintWithOnlyAPhoneCarriesNoHandle() throws Exception {
        authorize("gua:phone=+15551234567").andExpect(status().isFound());

        LoginSession session = parkedSession();
        assertThat(session.getPhoneHint()).isEqualTo("+15551234567");
        assertThat(session.getGenesisAttachHandle()).isNull();
    }

    @Test
    void aGuaPasskeyIntentSetsThePasskeyIntentAndNoPhonePrefill() throws Exception {
        authorize("gua:intent=passkey").andExpect(status().isFound());

        LoginSession session = parkedSession();
        assertThat(session.getIntent()).isEqualTo(LoginSession.Intent.PASSKEY);
        assertThat(session.getPhoneHint()).isNull();
    }

    @Test
    void anUnknownKeyIsRefused() throws Exception {
        authorize("gua:phone=+15551234567;colour=blue")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_login_hint"));
    }

    @Test
    void aDuplicatedKeyIsRefused() throws Exception {
        authorize("gua:phone=+15551234567;phone=+15559999999")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_login_hint"));
    }

    @Test
    void anUnparsablePairIsRefused() throws Exception {
        authorize("gua:phone").andExpect(status().isBadRequest());
        authorize("gua:=value").andExpect(status().isBadRequest());
        authorize("gua:phone=").andExpect(status().isBadRequest());
        authorize("gua:phone=+15551234567;;genesis=" + HANDLE).andExpect(status().isBadRequest());
    }

    @Test
    void aMalformedGenesisHandleIsRefused() throws Exception {
        authorize("gua:genesis=short").andExpect(status().isBadRequest());
        authorize("gua:genesis=has spaces in it and is long enough").andExpect(status().isBadRequest());
        authorize("gua:genesis=not+base64url/chars=====").andExpect(status().isBadRequest());
    }

    @Test
    void aPhoneThatIsNotE164IsRefused() throws Exception {
        authorize("gua:phone=5551234567").andExpect(status().isBadRequest());
    }

    @Test
    void withTheFeatureOffAGuaHintIsNotParsedAtAll() throws Exception {
        identityServiceProperties.getGenesis().setEnabled(false);

        authorize("gua:phone=+15551234567;genesis=" + HANDLE).andExpect(status().isFound());

        // Exactly what an identity-service without this grammar does: the "gua" prefix is not one of
        // the phone prefixes, so there is no prefill, no handle, and nothing else changes.
        LoginSession session = parkedSession();
        assertThat(session.getPhoneHint()).isNull();
        assertThat(session.getGenesisAttachHandle()).isNull();
        assertThat(session.getIntent()).isEqualTo(LoginSession.Intent.PHONE);
    }

    @Test
    void withTheFeatureOffAMalformedGuaHintStillDoesNotFailTheLogin() throws Exception {
        identityServiceProperties.getGenesis().setEnabled(false);

        authorize("gua:this is not a grammar at all").andExpect(status().isFound());
    }

    @Test
    void theReservedPasskeyHintKeepsItsMeaning() throws Exception {
        authorize("passkey").andExpect(status().isFound());

        LoginSession session = parkedSession();
        assertThat(session.getIntent()).isEqualTo(LoginSession.Intent.PASSKEY);
        assertThat(session.getPhoneHint()).isNull();
        assertThat(session.getGenesisAttachHandle()).isNull();
    }

    @Test
    void aPlainPhoneHintStillPrefills() throws Exception {
        authorize("+15551234567").andExpect(status().isFound());

        LoginSession session = parkedSession();
        assertThat(session.getPhoneHint()).isEqualTo("+15551234567");
        assertThat(session.getGenesisAttachHandle()).isNull();
    }

    @Test
    void aPrefixedPhoneHintStillPrefills() throws Exception {
        authorize("phone:+15551234567").andExpect(status().isFound());

        assertThat(parkedSession().getPhoneHint()).isEqualTo("+15551234567");
    }

    @Test
    void noHintAtAllIsStillFine() throws Exception {
        authorize(null).andExpect(status().isFound());

        LoginSession session = parkedSession();
        assertThat(session.getPhoneHint()).isNull();
        assertThat(session.getGenesisAttachHandle()).isNull();
    }
}
