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

/**
 * The claim the whole sheet exists to make, driven rather than asserted about a mock: a step-up taken in the
 * web sheet is a step-up {@code POST /account/authority/challenge} accepts, and it carries every control the
 * native one carries (ADM-009 decision 4 step 2, decision 9).
 *
 * <p>Four properties, and the last two are the ones that make this safe rather than merely convenient:
 *
 * <ul>
 * <li>a request that produced no factor of its own mints a challenge when, and only when, the sheet left a
 * proof for that account, that access token and that transition;</li>
 * <li>it is spent once, so a second transition needs a second sheet;</li>
 * <li>the fresh-factor hold is weighed on the credential the sheet observed, so the laundering path of
 * decision 9 rule 3 is closed on this route exactly as on the native one;</li>
 * <li>a request that carries its own proof never looks at the sheet, which is what keeps the existing
 * platforms unchanged.</li>
 * </ul>
 */
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
    /** The fresh-factor hold, when a test is about it. Every other test leaves it at zero. */
    private static final Duration HOLD = Duration.ofDays(7);
    /** Long past any hold, so a credential's age is never what decides a test that is not about it. */
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
        // The hold is measured against the wall clock inside UserSecurityService, which no test clock reaches,
        // so it is switched off here and switched on by the one test that is about it. A test that tried to
        // age a credential by moving a stub clock would be measuring the fixture instead.
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

        // No assertion in the request and no PIN in the request: exactly the Android case, where the platform
        // cannot produce an assertion at all. Before this existed, the only thing left was the PIN, and a
        // passkey-only account was told to add one to gain authority.
        AuthorityChallengeService.Minted minted = challenge(Purpose.ADOPT, null);
        assertThat(minted.challenge()).isNotBlank();

        // Minted on the factor the sheet observed, so the record's own hold checks weigh the passkey rather
        // than whatever the account happens to hold when the record arrives.
        assertThat(challengeRepository.findAll()).singleElement()
                .extracting(AuthorityChallenge::getFactor, AuthorityChallenge::getPurpose)
                .containsExactly(AuthFactor.PASSKEY, Purpose.ADOPT);

        // Single use. A second transition needs a second sheet, which is the whole of what "scoped to this
        // transition" buys.
        assertThat(refusalFor(() -> challenge(Purpose.ADOPT, null))).isEqualTo("authority_step_up_required");
    }

    @Test
    void aProofFromTheSheetIsUselessForAnotherTransitionOrAnotherSession() {
        webStepUps.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, Instant.now().minus(ESTABLISHED));

        assertThat(refusalFor(() -> challenge(Purpose.GRANT, null))).isEqualTo("authority_step_up_required");
        assertThat(refusalFor(() -> challengeFrom(OTHER_SESSION, Purpose.ADOPT, null)))
                .isEqualTo("authority_step_up_required");
        // And neither refusal spent it.
        assertThat(challenge(Purpose.ADOPT, null).challenge()).isNotBlank();
    }

    @Test
    void theFreshFactorHoldIsWeighedOnWhatTheSheetObserved() {
        // The laundering path of decision 9 rule 3, arriving by the new route: a recovery mints a
        // caller-chosen PIN, the attacker confirms it in the sheet, and the sheet must not be a way around the
        // hold the native path applies.
        properties.getSecurity().setPinResetCooldown(HOLD);
        webStepUps.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PIN, Instant.now());

        AuthorityTransitionException refusal = catchThrowableOfType(() -> challenge(Purpose.ADOPT, null),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_factor_too_fresh");
        assertThat(refusal.getRetryAfterSeconds()).isPositive();

        // Burned by the attempt, so a refusal is not a free retry once the clock has moved on: the sheet is
        // run again, under the hold that refused it.
        assertThat(webStepUpRepository.findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull(USER, SESSION,
                Purpose.ADOPT)).isEmpty();
    }

    @Test
    void aRequestThatProvedSomethingItselfNeverLooksAtTheSheet() {
        webStepUps.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, Instant.now().minus(ESTABLISHED));

        // The PIN in the request settles it, exactly as before the sheet existed.
        assertThat(challenge(Purpose.ADOPT, PIN).challenge()).isNotBlank();
        assertThat(challengeRepository.findAll()).singleElement()
                .extracting(AuthorityChallenge::getFactor).isEqualTo(AuthFactor.PIN);

        // And the sheet's proof is untouched, which is what "the native path is unchanged" means in practice.
        assertThat(webStepUpRepository.findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull(USER, SESSION,
                Purpose.ADOPT)).hasSize(1);
    }

    @Test
    void withNoSheetAndNoFactorTheAnswerIsStillThatOneIsNeeded() {
        // The refusal that was there before, in the same words, for a caller that has run nothing: the sheet
        // adds a way to satisfy this step-up and no way to skip it.
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

    /** A clock the test moves, so the holds are weighed against real elapsed time. */
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
