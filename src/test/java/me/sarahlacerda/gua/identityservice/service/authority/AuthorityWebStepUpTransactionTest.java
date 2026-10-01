// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.repository.AuthorityWebStepUpRepository;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
@Import(AuthorityWebStepUpTransactionTest.ProxiedService.class)
@EnableTransactionManagement
class AuthorityWebStepUpTransactionTest {

    private static final String USER = "@sarah:gua.global";
    private static final String SESSION = "a".repeat(64);
    private static final Instant NOW = Instant.parse("2026-09-26T12:00:00Z");
    private static final Instant LONG_AGO = NOW.minusSeconds(60L * 60 * 24 * 400);

    @TestConfiguration
    static class ProxiedService {
        @Bean
        AuthorityPolicy authorityPolicy() {
            // Not a bean: the application already contributes an IdentityServiceProperties, and a second is ambiguous.
            IdentityServiceProperties properties = new IdentityServiceProperties();
            properties.getAuthority().setEnabled(true);
            properties.getAuthority().setNativeClientIds(List.of("gua-ios"));
            return new AuthorityPolicy(properties, mock(UserSecurityService.class));
        }

        @Bean
        AuthorityWebStepUpService authorityWebStepUpService(AuthorityWebStepUpRepository repository,
                AuthorityPolicy policy) {
            return new AuthorityWebStepUpService(repository, policy, Clock.fixed(NOW, ZoneOffset.UTC));
        }
    }

    @Autowired
    private AuthorityWebStepUpService service;

    @Test
    /** NOT_SUPPORTED suspends the test transaction, so the proxied service has to start its own. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void theSheetsOwnEntryPointStartsItsOwnTransaction() {
        Instant expiresAt = service.proved(USER, SESSION, "ADOPT", AuthFactor.PASSKEY, LONG_AGO);

        assertThat(expiresAt).isAfter(NOW);

        Optional<AuthorityWebStepUpService.Proved> proof = service.consume(USER, SESSION, Purpose.ADOPT);
        assertThat(proof).isPresent();
        assertThat(proof.get().factor()).isEqualTo(AuthFactor.PASSKEY);
    }
}
