package me.sarahlacerda.gua.identityservice.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import me.sarahlacerda.gua.identityservice.controller.oidc.OidcDiscoveryController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.config.OidcSigningKeyConfig;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(OidcDiscoveryController.class)
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = {
    "oidc.issuer=https://identity.example.com"
})
@EnableConfigurationProperties(OidcProperties.class)
@Import(OidcSigningKeyConfig.class)
class OidcDiscoveryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private EndpointRateLimiter endpointRateLimiter;

    @Test
    void openidConfigurationExposesEndpoints() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").value("https://identity.example.com"))
            .andExpect(jsonPath("$.authorization_endpoint").value("https://identity.example.com/oauth2/authorize"))
            .andExpect(jsonPath("$.token_endpoint").value("https://identity.example.com/oauth2/token"))
            .andExpect(jsonPath("$.userinfo_endpoint").value("https://identity.example.com/userinfo"))
            .andExpect(jsonPath("$.jwks_uri").value("https://identity.example.com/.well-known/jwks.json"))
            .andExpect(jsonPath("$.id_token_signing_alg_values_supported[0]").value("RS256"))
            .andExpect(jsonPath("$.code_challenge_methods_supported[0]").value("S256"))
            .andExpect(jsonPath("$.token_endpoint_auth_methods_supported", org.hamcrest.Matchers.hasItem("none")));
    }

    @Test
    void jwksPublishesRsaPublicSigningKey() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
            .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
            .andExpect(jsonPath("$.keys[0].use").value("sig"))
            .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
            .andExpect(jsonPath("$.keys[0].e").isNotEmpty())
            .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }
}
