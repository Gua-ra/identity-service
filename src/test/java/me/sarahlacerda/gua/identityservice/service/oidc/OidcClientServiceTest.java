package me.sarahlacerda.gua.identityservice.service.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;

class OidcClientServiceTest {

    private OidcClientService clientService;

    @BeforeEach
    void setUp() {
        OidcProperties properties = new OidcProperties();
        OidcProperties.ClientRegistration relyingParty = new OidcProperties.ClientRegistration();
        relyingParty.setClientId("mas");
        relyingParty.setClientSecret("secret");
        OidcProperties.ClientRegistration app = new OidcProperties.ClientRegistration();
        app.setClientId("gua-ios");
        app.setApiAccess(true);
        properties.setClients(List.of(relyingParty, app));
        clientService = new OidcClientService(properties, new BCryptPasswordEncoder(4));
        clientService.initialize();
    }

    @Test
    void onlyAClientRegisteredWithApiAccessMayPresentItsTokensToTheBearerApi() {
        assertThat(clientService.grantsApiAccess("gua-ios")).isTrue();
        assertThat(clientService.grantsApiAccess("mas")).isFalse();
    }

    @Test
    void anUnknownOrMissingClientHasNoApiAccess() {
        assertThat(clientService.grantsApiAccess("some-other-app")).isFalse();
        assertThat(clientService.grantsApiAccess(null)).isFalse();
    }
}
