// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainHeadRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainRecordRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceCandidateRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityWebStepUpRepository;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.PinPolicy;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.LoggingSecurityAuditLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.mock;

@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
class AuthorityWebStepUpChallengeTest {

    private static final String USER = "@sarah:gua.global";
    private static final String NATIVE_CLIENT = "gua-android";
    private static final String SESSION = "a".repeat(64);
    private static final String OTHER_SESSION = "b".repeat(64);
    private static final String PIN = "481937";
    private static final Duration HOLD = Duration.ofDays(7);
    private static final Duration ESTABLISHED = Duration.ofDays(400);

    @Autowired
    private IdentityUserRepository userRepository;

    @Autowired
    private PasskeyCredentialRepository passkeyRepository;

    @Autowired
    private AuthorityChallengeRepository challengeRepository;

    @Autowired
    private AuthorityWebStepUpRepository webStepUpRepository;

    @Autowired
    private AuthorityChainHeadRepository headRepository;

    @Autowired
    private AuthorityChainRecordRepository recordRepository;

    @Autowired
    private AuthorityDeviceRepository deviceRepository;

    @Autowired
    private AuthorityDeviceCandidateRepository candidateRepository;

    @Autowired
    private AccountGenesisRepository genesisRepository;

    private IdentityServiceProperties properties;
    private StubClock clock;
    private UserSecurityService userSecurityService;
    private AuthorityWebStepUpService webStepUps;
    private AccountAuthorityService service;

    @BeforeEach
    void setUp() {
        clock = new StubClock(Instant.now());
        properties = new IdentityServiceProperties();
        properties.getAuthority().setEnabled(true);
        properties.getAuthority().setNativeClientIds(List.of(NATIVE_CLIENT));
        // UserSecurityService measures the hold against the wall clock, so only the test about the hold turns it on.
        properties.getSecurity().setPinResetCooldown(Duration.ZERO);

        PasswordEncoder encoder = new BCryptPasswordEncoder(4);
        LoggingSecurityAuditLogger audit = new LoggingSecurityAuditLogger();
        userSecurityService = new UserSecurityService(userRepository, encoder, properties,
                mock(DirectoryService.class), mock(PhoneNumberHasher.class), mock(OtpService.class), audit,
                mock(StringRedisTemplate.class), new PinPolicy());
        PasskeyService passkeyService = new PasskeyService(passkeyRepository, new LoginFlowProperties(),
                mock(StringRedisTemplate.class), new ObjectMapper());

        AuthorityPolicy policy = new AuthorityPolicy(properties, userSecurityService);
        webStepUps = new AuthorityWebStepUpService(webStepUpRepository, policy, clock);
        AuthorityStepUpService stepUps = new AuthorityStepUpService(passkeyService, userSecurityService, policy,
                webStepUps, audit);
        service = new AccountAuthorityService(policy, new AuthorityAccounts(genesisRepository),
                new AuthorityChallengeService(challengeRepository, policy,
                        new AuthorityChallengeBurn(challengeRepository)), stepUps, headRepository,
                recordRepository, deviceRepository, candidateRepository, mock(AuthorityNotifications.class),
                mock(AuthorityBackoff.class), AuthorityHeadPublisherFixtures.off(properties), audit, clock);

        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        genesisRepository.saveAndFlush(AccountGenesisRecord.attachedBootstrap(genesis.accountId().value(), USER,
                (short) genesis.version(), (short) genesis.suite(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.canonicalBytes()), clock.instant()));

        userSecurityService.setInitialPin(USER, PIN);
    }

    @Test
    void aProofFromTheSheetMintsTheChallengeAndIsSpentOnce() {
        webStepUps.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, Instant.now().minus(ESTABLISHED));

        AuthorityChallengeService.Minted minted = challenge(Purpose.ADOPT, null);
        assertThat(minted.challenge()).isNotBlank();

        assertThat(challengeRepository.findAll()).singleElement()
                .extracting(AuthorityChallenge::getFactor, AuthorityChallenge::getPurpose)
                .containsExactly(AuthFactor.PASSKEY, Purpose.ADOPT);

        assertThat(refusalFor(() -> challenge(Purpose.ADOPT, null))).isEqualTo("authority_step_up_required");
    }

    @Test
    void aProofFromTheSheetIsUselessForAnotherTransitionOrAnotherSession() {
        webStepUps.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, Instant.now().minus(ESTABLISHED));

        assertThat(refusalFor(() -> challenge(Purpose.GRANT, null))).isEqualTo("authority_step_up_required");
        assertThat(refusalFor(() -> challengeFrom(OTHER_SESSION, Purpose.ADOPT, null)))
                .isEqualTo("authority_step_up_required");
        assertThat(challenge(Purpose.ADOPT, null).challenge()).isNotBlank();
    }

    @Test
    void theFreshFactorHoldIsWeighedOnWhatTheSheetObserved() {
        properties.getSecurity().setPinResetCooldown(HOLD);
        webStepUps.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PIN, Instant.now());

        AuthorityTransitionException refusal = catchThrowableOfType(() -> challenge(Purpose.ADOPT, null),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_factor_too_fresh");
        assertThat(refusal.getRetryAfterSeconds()).isPositive();

        assertThat(webStepUpRepository.findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull(USER, SESSION,
                Purpose.ADOPT)).isEmpty();
    }

    @Test
    void aRequestThatProvedSomethingItselfNeverLooksAtTheSheet() {
        webStepUps.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, Instant.now().minus(ESTABLISHED));

        assertThat(challenge(Purpose.ADOPT, PIN).challenge()).isNotBlank();
        assertThat(challengeRepository.findAll()).singleElement()
                .extracting(AuthorityChallenge::getFactor).isEqualTo(AuthFactor.PIN);

        assertThat(webStepUpRepository.findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull(USER, SESSION,
                Purpose.ADOPT)).hasSize(1);
    }

    @Test
    void withNoSheetAndNoFactorTheAnswerIsStillThatOneIsNeeded() {
        assertThat(refusalFor(() -> challenge(Purpose.ADOPT, null))).isEqualTo("authority_step_up_required");
        assertThat(challengeRepository.count()).isZero();
    }

    @Test
    void withTheFlagOffTheSheetIsNotEvenConsulted() {
        properties.getAuthority().setEnabled(true);
        webStepUps.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, Instant.now().minus(ESTABLISHED));
        properties.getAuthority().setEnabled(false);

        assertThat(refusalFor(() -> challenge(Purpose.ADOPT, null))).isEqualTo("authority_disabled");
        assertThat(challengeRepository.count()).isZero();
        assertThat(webStepUpRepository.findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull(USER, SESSION,
                Purpose.ADOPT)).hasSize(1);
    }

    private AuthorityChallengeService.Minted challenge(Purpose purpose, String pin) {
        return challengeFrom(SESSION, purpose, pin);
    }

    private AuthorityChallengeService.Minted challengeFrom(String sessionHash, Purpose purpose, String pin) {
        return service.challenge(USER, Optional.of(NATIVE_CLIENT), sessionHash, purpose, null, null, pin,
                "127.0.0.1");
    }

    private static String refusalFor(Runnable call) {
        AuthorityTransitionException refusal = catchThrowableOfType(call::run, AuthorityTransitionException.class);
        assertThat(refusal).as("a refusal was expected").isNotNull();
        return refusal.getCode();
    }

    private static final class StubClock extends Clock {

        private Instant now;

        private StubClock(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
