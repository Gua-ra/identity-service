// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * The challenge is the freshness of every record in the chain, so these are its properties stated as behaviour:
 * 32 bytes, minted once, bound to the account, the session and the purpose, single use, and burned on refusal as
 * well as on acceptance.
 */
class AuthorityChallengeServiceTest {

    private static final String ACCOUNT = "ga1aea6aqb5opmzmutench3ggzepkhgwmkajb3epqqrhckkf7bcbcwl2cy";
    private static final String SESSION = "0".repeat(64);

    private InMemoryChallenges repository;
    private AuthorityChallengeService challenges;
    private Instant now;

    @BeforeEach
    void setUp() {
        repository = new InMemoryChallenges();
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getAuthority().setEnabled(true);
        challenges = new AuthorityChallengeService(repository, new AuthorityPolicy(properties, null),
                new AuthorityChallengeBurn(repository));
        now = Instant.parse("2026-09-19T12:00:00Z");
    }

    @Test
    void aMintedChallengeIsThirtyTwoBytesAndStoredOnlyAsItsHash() {
        AuthorityChallengeService.Minted minted = mint(Purpose.ADOPT);

        assertThat(java.util.Base64.getUrlDecoder().decode(minted.challenge())).hasSize(32);
        assertThat(minted.expiresAt()).isEqualTo(now.plus(Duration.ofMinutes(15)));
        // Never the value itself. A dump of this table hands nobody a challenge to sign.
        assertThat(repository.rows).hasSize(1);
        assertThat(repository.rows.get(0).getChallengeHash()).isNotEqualTo(minted.challenge());
        assertThat(repository.rows.get(0).getChallengeHash()).hasSize(64);
    }

    @Test
    void spendingReturnsTheBytesAndTheFactorThatMintedIt() {
        Instant credentialAge = now.minus(Duration.ofDays(30));
        AuthorityChallengeService.Minted minted = challenges.mint(ACCOUNT, SESSION, Purpose.GRANT,
                AuthFactor.PASSKEY, credentialAge, now);

        AuthorityChallengeService.Spent spent = challenges.spend(ACCOUNT, SESSION, Purpose.GRANT,
                minted.challenge(), now);

        assertThat(spent.challenge()).hasSize(32);
        // The factor travels with the challenge, so the hold is weighed on the credential actually presented.
        assertThat(spent.factor()).isEqualTo(AuthFactor.PASSKEY);
        assertThat(spent.factorCreatedAt()).isEqualTo(credentialAge);
    }

    @Test
    void aChallengeIsSingleUse() {
        AuthorityChallengeService.Minted minted = mint(Purpose.ADOPT);
        challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, minted.challenge(), now);

        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, minted.challenge(), now)))
                .isEqualTo("authority_challenge_invalid");
    }

    @Test
    void aChallengeMintedForAnotherSessionIsRefusedAndBurned() {
        AuthorityChallengeService.Minted minted = mint(Purpose.ADOPT);

        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, "1".repeat(64), Purpose.ADOPT, minted.challenge(),
                now))).isEqualTo("authority_challenge_invalid");
        // Burned on refusal, so a captured request body is useless even to the session that was entitled to it.
        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, minted.challenge(), now)))
                .isEqualTo("authority_challenge_invalid");
    }

    @Test
    void aChallengeMintedForAnotherPurposeIsRefusedAndBurned() {
        AuthorityChallengeService.Minted minted = mint(Purpose.ADOPT);

        // A step-up taken for one transition does not carry over to another.
        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, SESSION, Purpose.RECOVER, minted.challenge(), now)))
                .isEqualTo("authority_challenge_invalid");
        assertThat(repository.rows.get(0).getSpentAt()).isEqualTo(now);
    }

    @Test
    void aChallengeMintedForAnotherAccountIsRefused() {
        AuthorityChallengeService.Minted minted = mint(Purpose.ADOPT);

        assertThat(refusalFrom(() -> challenges.spend("ga1aeadtzzdbh5kutyq2zczf4rp76qirr4xn4ucwibfoilhsjcxuiedcey",
                SESSION, Purpose.ADOPT, minted.challenge(), now))).isEqualTo("authority_challenge_invalid");
    }

    @Test
    void anExpiredChallengeIsRefused() {
        AuthorityChallengeService.Minted minted = mint(Purpose.ADOPT);

        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, minted.challenge(),
                minted.expiresAt()))).isEqualTo("authority_challenge_invalid");
    }

    @Test
    void aChallengeNobodyMintedIsRefusedInTheSameWords() {
        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", now))).isEqualTo("authority_challenge_invalid");
        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, "  ", now)))
                .isEqualTo("authority_challenge_invalid");
    }

    @Test
    void cancellingATransitionBurnsEveryUnspentChallengeOfThatPurpose() {
        AuthorityChallengeService.Minted first = mint(Purpose.ADOPT);
        AuthorityChallengeService.Minted second = mint(Purpose.ADOPT);

        challenges.burnUnspent(ACCOUNT, Purpose.ADOPT, now);

        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, first.challenge(), now)))
                .isEqualTo("authority_challenge_invalid");
        assertThat(refusalFrom(() -> challenges.spend(ACCOUNT, SESSION, Purpose.ADOPT, second.challenge(), now)))
                .isEqualTo("authority_challenge_invalid");
    }

    @Test
    void mintingSweepsExpiredRowsOnTheWritePathRatherThanOnASchedule() {
        mint(Purpose.ADOPT);
        now = now.plus(Duration.ofHours(1));

        mint(Purpose.GRANT);

        // Nothing in this application enables scheduling, and an expired challenge is already refused when it
        // is spent, so this only stops them piling up.
        assertThat(repository.deletions).isEqualTo(1);
        assertThat(repository.rows).hasSize(1);
    }

    private AuthorityChallengeService.Minted mint(Purpose purpose) {
        return challenges.mint(ACCOUNT, SESSION, purpose, AuthFactor.PIN, now.minus(Duration.ofDays(30)), now);
    }

    private static String refusalFrom(Runnable action) {
        AuthorityTransitionException refusal =
                catchThrowableOfType(action::run, AuthorityTransitionException.class);
        assertThat(refusal).as("expected a refusal").isNotNull();
        return refusal.getCode();
    }

    /**
     * A repository that behaves, rather than a mock that agrees. The properties under test are about what is
     * stored and what a second lookup finds, so a stub returning canned answers would prove nothing.
     */
    private static final class InMemoryChallenges
            implements me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository {

        private final List<AuthorityChallenge> rows = new ArrayList<>();
        private final Map<String, AuthorityChallenge> byHash = new HashMap<>();
        private int deletions;

        @Override
        public Optional<AuthorityChallenge> findByChallengeHash(String challengeHash) {
            return Optional.ofNullable(byHash.get(challengeHash));
        }

        @Override
        public List<AuthorityChallenge> findByAccountAndPurposeAndSpentAtIsNull(String account, Purpose purpose) {
            return rows.stream()
                    .filter(row -> row.getAccount().equals(account))
                    .filter(row -> row.getPurpose() == purpose)
                    .filter(row -> row.getSpentAt() == null)
                    .toList();
        }

        @Override
        public int deleteExpired(Instant cutoff) {
            List<AuthorityChallenge> expired = rows.stream()
                    .filter(row -> row.getExpiresAt().isBefore(cutoff))
                    .toList();
            expired.forEach(row -> {
                rows.remove(row);
                byHash.remove(row.getChallengeHash());
            });
            if (!expired.isEmpty()) {
                deletions++;
            }
            return expired.size();
        }

        @Override
        public <S extends AuthorityChallenge> S save(S entity) {
            if (!rows.contains(entity)) {
                rows.add(entity);
            }
            byHash.put(entity.getChallengeHash(), entity);
            return entity;
        }

        // Nothing below is reached by this service, and a call to any of it would be a change worth noticing.
        @Override
        public <S extends AuthorityChallenge> List<S> saveAll(Iterable<S> entities) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<AuthorityChallenge> findById(java.util.UUID id) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean existsById(java.util.UUID id) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<AuthorityChallenge> findAll() {
            return List.copyOf(rows);
        }

        @Override
        public List<AuthorityChallenge> findAllById(Iterable<java.util.UUID> ids) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long count() {
            return rows.size();
        }

        @Override
        public void deleteById(java.util.UUID id) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void delete(AuthorityChallenge entity) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteAllById(Iterable<? extends java.util.UUID> ids) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteAll(Iterable<? extends AuthorityChallenge> entities) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteAll() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void flush() {
        }

        @Override
        public <S extends AuthorityChallenge> S saveAndFlush(S entity) {
            return save(entity);
        }

        @Override
        public <S extends AuthorityChallenge> List<S> saveAllAndFlush(Iterable<S> entities) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteAllInBatch(Iterable<AuthorityChallenge> entities) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteAllByIdInBatch(Iterable<java.util.UUID> ids) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteAllInBatch() {
            throw new UnsupportedOperationException();
        }

        @Override
        public AuthorityChallenge getOne(java.util.UUID id) {
            throw new UnsupportedOperationException();
        }

        @Override
        public AuthorityChallenge getById(java.util.UUID id) {
            throw new UnsupportedOperationException();
        }

        @Override
        public AuthorityChallenge getReferenceById(java.util.UUID id) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <S extends AuthorityChallenge> Optional<S> findOne(
                org.springframework.data.domain.Example<S> example) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <S extends AuthorityChallenge> List<S> findAll(org.springframework.data.domain.Example<S> example) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <S extends AuthorityChallenge> List<S> findAll(org.springframework.data.domain.Example<S> example,
                org.springframework.data.domain.Sort sort) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <S extends AuthorityChallenge> org.springframework.data.domain.Page<S> findAll(
                org.springframework.data.domain.Example<S> example,
                org.springframework.data.domain.Pageable pageable) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <S extends AuthorityChallenge> long count(org.springframework.data.domain.Example<S> example) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <S extends AuthorityChallenge> boolean exists(org.springframework.data.domain.Example<S> example) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <S extends AuthorityChallenge, R> R findBy(org.springframework.data.domain.Example<S> example,
                java.util.function.Function<org.springframework.data.repository.query.FluentQuery
                        .FetchableFluentQuery<S>, R> queryFunction) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<AuthorityChallenge> findAll(org.springframework.data.domain.Sort sort) {
            throw new UnsupportedOperationException();
        }

        @Override
        public org.springframework.data.domain.Page<AuthorityChallenge> findAll(
                org.springframework.data.domain.Pageable pageable) {
            throw new UnsupportedOperationException();
        }
    }
}
