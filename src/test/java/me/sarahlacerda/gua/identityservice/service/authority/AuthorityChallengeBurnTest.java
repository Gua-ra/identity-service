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
 * A spent challenge stays spent when the request that spent it is refused (ADM-009 decision 2).
 *
 * <p>This one has to be driven through a real transaction, because the defect it pins is invisible without
 * one. Every other test here runs inside a single test-managed transaction that never commits and never rolls
 * back, so a burn written into the caller's transaction looks perfectly durable; in production every refusal
 * after the spend throws out of that transaction and took the burn with it, and one passkey assertion or PIN
 * entry paid for unlimited submission attempts inside the challenge's fifteen minutes.
 *
 * <p>So the test transaction is switched off ({@code NOT_SUPPORTED}) and the caller's transaction is driven
 * explicitly, with the beans wired as Spring wires them: {@code REQUIRES_NEW} is applied by the proxy, and a
 * hand-constructed service has no proxy at all.
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

        // Exactly the shape of the submission path: the challenge is spent, and then something later refuses
        // the record. AuthorityTransitionException and InvalidAuthorityRecordException are both unchecked, and
        // nothing in the feature declares noRollbackFor.
        assertThatThrownBy(() -> transaction.execute(status -> {
            challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, challenge, NOW);
            throw new IllegalStateException("the record was refused after its challenge was spent");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(challenges.find(challenge).orElseThrow().getSpentAt()).isEqualTo(NOW);

        // And the captured request body is not replayable with it, which is the property decision 2 states.
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

        // Spent for another purpose: refused, and burned, so a caller cannot grind the four bindings.
        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> transaction.execute(status -> challenges.spend(ACCOUNT, SESSION, Purpose.REVOKE, challenge,
                        NOW)),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(challenges.find(challenge).orElseThrow().getSpentAt()).isEqualTo(NOW);
        assertThat(repository.findByAccountAndPurposeAndSpentAtIsNull(ACCOUNT, Purpose.GRANT)).isEmpty();
    }

    /**
     * The three beans as the application wires them, so the proxy that carries {@code REQUIRES_NEW} exists.
     *
     * <p>The policy's user-security collaborator is not reached by anything here: no hold is weighed while a
     * challenge is minted or spent.
     */
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
