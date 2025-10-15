package me.sarahlacerda.gua.identityservice.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(OidcDiscoveryController.class)
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = {
    "oidc.issuer=https://identity.example.com",
    "oidc.jwt-signing-secret=test-signing-secret"
})
@EnableConfigurationProperties(OidcProperties.class)
class OidcDiscoveryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private EndpointRateLimiter endpointRateLimiter;

    @Test
    void openidConfigurationExposesEndpoints() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").value("https://identity.example.com"))
            .andExpect(jsonPath("$.authorization_endpoint").value("https://identity.example.com/oauth2/authorize"))
            .andExpect(jsonPath("$.token_endpoint").value("https://identity.example.com/oauth2/token"))
            .andExpect(jsonPath("$.userinfo_endpoint").value("https://identity.example.com/userinfo"))
            .andExpect(jsonPath("$.jwks_uri").value("https://identity.example.com/.well-known/jwks.json"));
    }

    @Test
    void jwksPublishesSigningKeyMetadata() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys[0].kty").value("oct"))
            .andExpect(jsonPath("$.keys[0].alg").value("HS256"))
            .andExpect(jsonPath("$.keys[0].use").value("sig"))
            .andExpect(jsonPath("$.keys[0].k").isNotEmpty());
    }
}
