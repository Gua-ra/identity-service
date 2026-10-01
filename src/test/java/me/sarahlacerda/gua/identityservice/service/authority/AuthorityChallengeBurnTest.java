// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Runs outside the test transaction and on Spring-wired beans: the caller's rollback has to be real, and
 * {@code REQUIRES_NEW} is applied only through the proxy.
 */
@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
@Import(AuthorityChallengeBurnTest.Beans.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuthorityChallengeBurnTest {

    private static final String ACCOUNT = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz";
    private static final String SESSION = "c".repeat(64);
    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Autowired
    private AuthorityChallengeService challenges;

    @Autowired
    private AuthorityChallengeRepository repository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    void aChallengeSpentByARequestThatIsThenRefusedStaysSpent() {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        String challenge = transaction.execute(status -> challenges
                .mint(ACCOUNT, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, NOW.minus(Duration.ofDays(30)), NOW)
                .challenge());

        assertThatThrownBy(() -> transaction.execute(status -> {
            challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, challenge, NOW);
            throw new IllegalStateException("the record was refused after its challenge was spent");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(challenges.find(challenge).orElseThrow().getSpentAt()).isEqualTo(NOW);

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> transaction.execute(status -> challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, challenge,
                        NOW)),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_challenge_invalid");
    }

    @Test
    void aChallengeRefusedForItsBindingIsBurnedTheSameWay() {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        String challenge = transaction.execute(status -> challenges
                .mint(ACCOUNT, SESSION, Purpose.GRANT, AuthFactor.PIN, NOW.minus(Duration.ofDays(30)), NOW)
                .challenge());

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> transaction.execute(status -> challenges.spend(ACCOUNT, SESSION, Purpose.REVOKE, challenge,
                        NOW)),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(challenges.find(challenge).orElseThrow().getSpentAt()).isEqualTo(NOW);
        assertThat(repository.findByAccountAndPurposeAndSpentAtIsNull(ACCOUNT, Purpose.GRANT)).isEmpty();
    }

    @Test
    void aChallengeSpentByAnotherRequestAfterThisOneReadItIsRefused() {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        TransactionTemplate otherRequest = new TransactionTemplate(transactionManager);
        otherRequest.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        String challenge = transaction.execute(status -> challenges
                .mint(ACCOUNT, SESSION, Purpose.NOTIFY, null, null, NOW)
                .challenge());

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> transaction.execute(status -> {
                    assertThat(challenges.find(challenge).orElseThrow().getSpentAt()).isNull();
                    otherRequest.execute(other -> challenges.spend(ACCOUNT, SESSION, Purpose.NOTIFY, challenge,
                            NOW));
                    return challenges.spend(ACCOUNT, SESSION, Purpose.NOTIFY, challenge, NOW);
                }),
                AuthorityTransitionException.class);

        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_challenge_invalid");
    }

    @TestConfiguration
    static class Beans {

        @Bean
        AuthorityPolicy authorityPolicy() {
            IdentityServiceProperties properties = new IdentityServiceProperties();
            properties.getAuthority().setEnabled(true);
            return new AuthorityPolicy(properties, null);
        }

        @Bean
        AuthorityChallengeBurn authorityChallengeBurn(AuthorityChallengeRepository repository) {
            return new AuthorityChallengeBurn(repository);
        }

        @Bean
        AuthorityChallengeService authorityChallengeService(AuthorityChallengeRepository repository,
                AuthorityPolicy policy, AuthorityChallengeBurn burn) {
            return new AuthorityChallengeService(repository, policy, burn);
        }
    }
}
