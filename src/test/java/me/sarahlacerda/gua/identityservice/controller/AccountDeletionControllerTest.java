package me.sarahlacerda.gua.identityservice.controller;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.controller.oidc.AccountDeletionController;
import me.sarahlacerda.gua.identityservice.service.account.AccountDeletionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

/**
 * Who may report which deletion: two confidential clients, each the authentication service of its own
 * homeserver, and a third bound to none. Real client registry, real homeserver registry, real
 * secret check; only the deletion itself is a mock.
 */
@WebMvcTest(AccountDeletionController.class)
@Import({ OidcClientService.class, HomeserverRegistry.class, AccountDeletionControllerTest.Encoder.class })
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = {
        "oidc.issuer=https://identity.example.com",
        "oidc.account-deletion-notices-enabled=true",
        "oidc.clients[0].client-id=mas-a",
        "oidc.clients[0].client-secret=secret-a",
        "oidc.clients[0].homeserver-ids=hs-a",
        "oidc.clients[1].client-id=mas-b",
        "oidc.clients[1].client-secret=secret-b",
        "oidc.clients[1].homeserver-ids=hs-b",
        "oidc.clients[2].client-id=mas-none",
        "oidc.clients[2].client-secret=secret-none",
        "oidc.clients[3].client-id=gua-ios",
        "oidc.clients[3].homeserver-ids=hs-a",
        "identity.routing.default-homeserver-id=hs-a",
        "identity.routing.homeservers[0].id=hs-a",
        "identity.routing.homeservers[0].domain=a.example",
        "identity.routing.homeservers[0].admin-api-base-url=http://a.invalid",
        "identity.routing.homeservers[0].client-api-base-url=https://a.example",
        "identity.routing.homeservers[0].admin-access-token=unused",
        "identity.routing.homeservers[1].id=hs-b",
        "identity.routing.homeservers[1].domain=b.example",
        "identity.routing.homeservers[1].admin-api-base-url=http://b.invalid",
        "identity.routing.homeservers[1].client-api-base-url=https://b.example",
        "identity.routing.homeservers[1].admin-access-token=unused"
})
class AccountDeletionControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    OidcProperties oidcProperties;

    @MockitoBean
    AccountDeletionService accountDeletionService;

    @MockitoBean
    EndpointRateLimiter endpointRateLimiter;

    @Test
    void eachClientMayReportAccountsOnItsOwnHomeserver() throws Exception {
        notice("mas-a", "secret-a", "@alice:a.example").andExpect(status().isNoContent());
        notice("mas-b", "secret-b", "@bob:b.example").andExpect(status().isNoContent());

        verify(accountDeletionService).delete("@alice:a.example");
        verify(accountDeletionService).delete("@bob:b.example");
    }

    @Test
    void noClientMayReportAccountsOnAnotherHomeserver() throws Exception {
        notice("mas-a", "secret-a", "@bob:b.example")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("unauthorized_client"));
        notice("mas-b", "secret-b", "@alice:a.example")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("unauthorized_client"));

        verify(accountDeletionService, never()).delete(anyString());
    }

    @Test
    void aClientBoundToNoHomeserverMayReportNothing() throws Exception {
        notice("mas-none", "secret-none", "@alice:a.example").andExpect(status().isForbidden());
        notice("mas-none", "secret-none", "@bob:b.example").andExpect(status().isForbidden());

        verify(accountDeletionService, never()).delete(anyString());
    }

    @Test
    void aPublicClientIsRefusedWhateverItsRegistrationLists() throws Exception {
        notice("gua-ios", null, "@alice:a.example").andExpect(status().isUnauthorized());

        verify(accountDeletionService, never()).delete(anyString());
    }

    @Test
    void anotherClientsSecretAuthenticatesNobody() throws Exception {
        notice("mas-b", "secret-a", "@bob:b.example").andExpect(status().isUnauthorized());

        verify(accountDeletionService, never()).delete(anyString());
    }

    @Test
    void whileTheNoticeIsTurnedOffEveryCallerIsRefusedBeforeItsCredentialsAreRead() throws Exception {
        oidcProperties.setAccountDeletionNoticesEnabled(false);
        try {
            notice("mas-a", "secret-a", "@alice:a.example")
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(jsonPath("$.code").value("account_deletion_notices_disabled"));
            notice("mas-a", "wrong", "@alice:a.example").andExpect(status().isServiceUnavailable());
        } finally {
            oidcProperties.setAccountDeletionNoticesEnabled(true);
        }

        verify(accountDeletionService, never()).delete(anyString());
    }

    private ResultActions notice(String clientId, String clientSecret, String sub) throws Exception {
        var request = post("/oauth2/account-deleted")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", clientId)
                .param("sub", sub);
        if (clientSecret != null) {
            request.param("client_secret", clientSecret);
        }
        return mockMvc.perform(request);
    }

    static class Encoder {
        @Bean
        @Primary
        PasswordEncoder testPasswordEncoder() {
            return new BCryptPasswordEncoder(4);
        }
    }
}
