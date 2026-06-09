package me.sarahlacerda.gua.identityservice.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;

import com.nimbusds.jose.jwk.RSAKey;

import me.sarahlacerda.gua.identityservice.controller.oidc.OidcUserInfoController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.config.OidcSigningKeyConfig;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(OidcUserInfoController.class)
@Import({OidcUserInfoControllerTest.TestConfiguration.class, OidcSigningKeyConfig.class})
@TestPropertySource(properties = {
    "oidc.issuer=https://identity.example.com"
})
@org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc(addFilters = false)
class OidcUserInfoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private OidcTokenService tokenService;

    @MockitoBean
    private EndpointRateLimiter endpointRateLimiter;

    private OidcTokenResponse tokens;

    @BeforeEach
    void setUp() {
        tokens = tokenService.issueTokens(new OidcAuthorization(
            "user-123",
            "+15551234567",
            "Alice",
            Set.of("openid", "profile"),
            "mas"
        ));
    }

    @Test
    void userInfoReturnsClaimsFromAccessToken() throws Exception {
        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + tokens.accessToken()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sub").value("user-123"))
            .andExpect(jsonPath("$.phone_number").value("+15551234567"))
            .andExpect(jsonPath("$.name").value("Alice"));
    }

    static class TestConfiguration {

        @Bean
        OidcTokenService oidcTokenService(OidcProperties properties, RSAKey oidcSigningKey) {
            return new OidcTokenService(properties, oidcSigningKey);
        }
    }
}
