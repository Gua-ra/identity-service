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

/**
 * The hosted sheet's own entry point, called with no transaction around it, on a proxied bean.
 *
 * <p>This exists because a real bug lived through three tests that all looked like they covered it. The sheet
 * verified a passkey assertion, posted it, and the server answered 500: the write path's housekeeping delete
 * ran outside a transaction and Hibernate refused it. Every completed hosted ceremony failed, for everyone,
 * while the page reported a generic passkey failure and the walk read as "the ceremony does not complete".
 *
 * <p>Why the existing tests could not see it. {@code LoginFlowControllerTest} is a {@code @WebMvcTest} with
 * this service mocked, so it verifies the arguments and never runs it. {@code AuthorityWebStepUpServiceTest}
 * builds the service with {@code new}, so there is no proxy and {@code @Transactional} is inert, and
 * {@code @DataJpaTest} wraps each test in a transaction of its own, which supplied the very thing that was
 * missing. Both had to be false at once for the bug to be visible, so this test makes both false: the bean is
 * the proxied one, and the test declares no transaction.
 *
 * <p>So the assertion worth making here is not about a field. It is that the call the controller makes writes
 * a row and does not throw, which is exactly what production could not do.
 */
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
        /**
         * Built here rather than published as a bean: the application already contributes an
         * {@code IdentityServiceProperties}, and a second one of the same type only makes the injection
         * ambiguous. Nothing else in this slice reads it.
         */
        @Bean
        AuthorityPolicy authorityPolicy() {
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

    /**
     * NOT_SUPPORTED, deliberately: it suspends the transaction {@code @DataJpaTest} would otherwise open, so
     * the service has to start its own exactly as it does behind a request. With the annotation removed from
     * the string overload this fails with InvalidDataAccessApiUsageException, which is the production 500.
     */
    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void theSheetsOwnEntryPointStartsItsOwnTransaction() {
        Instant expiresAt = service.proved(USER, SESSION, "ADOPT", AuthFactor.PASSKEY, LONG_AGO);

        assertThat(expiresAt).isAfter(NOW);

        // And the proof is really there afterwards, in its own transaction, which is the other half: a write
        // that rolled back silently would leave the sheet reporting success and the challenge unspendable.
        Optional<AuthorityWebStepUpService.Proved> proof = service.consume(USER, SESSION, Purpose.ADOPT);
        assertThat(proof).isPresent();
        assertThat(proof.get().factor()).isEqualTo(AuthFactor.PASSKEY);
    }
}
