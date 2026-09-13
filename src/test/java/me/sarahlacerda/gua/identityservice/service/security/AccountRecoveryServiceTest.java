package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryCooldownException;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryNotReadyException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.WeakPinException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState.Status;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * The delayed account recovery against a clock the test moves, so every status is pinned at the
 * exact instant it changes rather than somewhere around it.
 *
 * <p>
 * The real {@link UserSecurityService} runs underneath over a mocked repository, so the row the
 * recovery reads and writes is the row the rest of the service would see.
 */
class AccountRecoveryServiceTest {

    private static final String USER = "@alice:gua.global";
    private static final Duration DORMANCY = Duration.ofDays(7);
    private static final Duration WAIT = Duration.ofDays(3);
    /** wait + max(wait, dormancy) */
    private static final Duration LIFE = WAIT.plus(DORMANCY);
    private static final Instant T0 = Instant.parse("2026-09-01T10:15:30Z");

    private final MutableClock clock = new MutableClock(T0);
    private IdentityUserRepository repository;
    private PasskeyService passkeyService;
    private EndOtherSessionsService endOtherSessionsService;
    private SecurityAuditLogger auditLogger;
    private IdentityServiceProperties properties;
    private PasswordEncoder passwordEncoder;
    private AccountRecoveryService service;
    private IdentityUser user;

    @BeforeEach
    void setUp() {
        repository = mock(IdentityUserRepository.class);
        passkeyService = mock(PasskeyService.class);
        endOtherSessionsService = mock(EndOtherSessionsService.class);
        auditLogger = mock(SecurityAuditLogger.class);
        passwordEncoder = new BCryptPasswordEncoder(4);
        properties = new IdentityServiceProperties();
        properties.getSecurity().setAccountRecoveryDormancy(DORMANCY);
        properties.getSecurity().setAccountRecoveryWait(WAIT);
        UserSecurityService userSecurityService = new UserSecurityService(repository, passwordEncoder, properties,
                mock(DirectoryService.class), mock(PhoneNumberHasher.class), mock(OtpService.class), auditLogger,
                mock(StringRedisTemplate.class), new PinPolicy());
        service = new AccountRecoveryService(userSecurityService, passkeyService, endOtherSessionsService, properties,
                auditLogger, clock);

        user = IdentityUser.builder().userId(USER).build();
        user.setPinHash(passwordEncoder.encode("482913"));
        when(repository.findByUserId(USER)).thenReturn(Optional.of(user));
        when(repository.findByUserIdForUpdate(USER)).thenReturn(Optional.of(user));
    }

    // -------------------- status, at every boundary --------------------

    @Test
    void anAccountThatNeverSignedInAndHasNoEpisodeIsAvailable() {
        assertThat(service.stateFor(USER)).isEqualTo(new AccountRecoveryState(Status.AVAILABLE, null, null, null));
    }

    @Test
    void anAccountWithNoRowAtAllIsAvailable() {
        when(repository.findByUserId(USER)).thenReturn(Optional.empty());

        assertThat(service.stateFor(USER).status()).isEqualTo(Status.AVAILABLE);
    }

    @Test
    void aSignInInsideTheDormancyPeriodIsTooSoonUntilTheInstantItEnds() {
        user.setLastLoginAt(T0.minus(DORMANCY));

        clock.set(T0.minusNanos(1));
        assertThat(service.stateFor(USER).status()).isEqualTo(Status.TOO_SOON);

        clock.set(T0);
        assertThat(service.stateFor(USER).status()).isEqualTo(Status.AVAILABLE);
    }

    /** The published time is rounded up to a whole UTC hour so it does not give away the sign-in time. */
    @Test
    void tooSoonPublishesTheNextWholeHourAfterTheDormancyEnds() {
        user.setLastLoginAt(Instant.parse("2026-09-01T10:15:30Z"));

        AccountRecoveryState state = service.stateFor(USER);

        assertThat(state.status()).isEqualTo(Status.TOO_SOON);
        assertThat(state.availableAtEpochSeconds())
                .isEqualTo(Instant.parse("2026-09-08T11:00:00Z").getEpochSecond());
        assertThat(state.completableAtEpochSeconds()).isNull();
        assertThat(state.expiresAtEpochSeconds()).isNull();
    }

    @Test
    void aDormancyEndingExactlyOnTheHourIsNotPushedAnotherHour() {
        user.setLastLoginAt(Instant.parse("2026-09-01T10:00:00Z"));

        assertThat(service.stateFor(USER).availableAtEpochSeconds())
                .isEqualTo(Instant.parse("2026-09-08T10:00:00Z").getEpochSecond());
    }

    /**
     * With short testing durations a whole hour would dwarf a dormancy of minutes, so the published
     * time is rounded up to the next whole minute instead.
     */
    @Test
    void underShortTestingDurationsTooSoonPublishesTheNextWholeMinute() {
        useShortTestingDurations();
        user.setLastLoginAt(Instant.parse("2026-09-01T10:14:20Z"));

        AccountRecoveryState state = service.stateFor(USER);

        assertThat(state.status()).isEqualTo(Status.TOO_SOON);
        assertThat(state.availableAtEpochSeconds())
                .isEqualTo(Instant.parse("2026-09-01T10:18:00Z").getEpochSecond());
    }

    @Test
    void underShortTestingDurationsADormancyEndingExactlyOnTheMinuteIsNotPushedAnotherMinute() {
        useShortTestingDurations();
        user.setLastLoginAt(Instant.parse("2026-09-01T10:15:00Z"));

        assertThat(service.stateFor(USER).availableAtEpochSeconds())
                .isEqualTo(Instant.parse("2026-09-01T10:18:00Z").getEpochSecond());
    }

    private void useShortTestingDurations() {
        properties.getSecurity().setAccountRecoveryDormancy(Duration.ofMinutes(3));
        properties.getSecurity().setAccountRecoveryWait(Duration.ofMinutes(2));
        properties.getSecurity().setAccountRecoveryAllowShortForTesting(true);
    }

    @Test
    void anEpisodeIsPendingUntilTheWaitEndsAndReadyFromThatInstant() {
        Instant stamp = T0.minus(WAIT);
        user.setPinResetRequestedAt(stamp);

        clock.set(stamp.plus(WAIT).minusNanos(1));
        AccountRecoveryState pending = service.stateFor(USER);
        assertThat(pending.status()).isEqualTo(Status.PENDING);
        assertThat(pending.completableAtEpochSeconds()).isEqualTo(stamp.plus(WAIT).getEpochSecond());
        assertThat(pending.expiresAtEpochSeconds()).isEqualTo(stamp.plus(LIFE).getEpochSecond());
        assertThat(pending.availableAtEpochSeconds()).isNull();

        clock.set(stamp.plus(WAIT));
        assertThat(service.stateFor(USER).status()).isEqualTo(Status.READY);
    }

    @Test
    void anEpisodeIsReadyUntilItsLifeEndsAndDeadFromThatInstant() {
        Instant stamp = T0.minus(LIFE);
        user.setPinResetRequestedAt(stamp);

        clock.set(stamp.plus(LIFE).minusNanos(1));
        assertThat(service.stateFor(USER).status()).isEqualTo(Status.READY);

        // A dead stamp is treated as absent: nothing about it may satisfy a later wait.
        clock.set(stamp.plus(LIFE));
        assertThat(service.stateFor(USER).status()).isEqualTo(Status.AVAILABLE);
    }

    @Test
    void aLiveEpisodeIsReportedEvenWhenTheAccountWasUsedInsideTheDormancyPeriod() {
        user.setPinResetRequestedAt(T0.minus(Duration.ofDays(1)));
        user.setLastLoginAt(T0.minus(Duration.ofHours(1)));

        assertThat(service.stateFor(USER).status()).isEqualTo(Status.PENDING);
    }

    @Test
    void aDeadEpisodeFallsBackToTheDormancyRule() {
        user.setPinResetRequestedAt(T0.minus(LIFE).minusSeconds(1));
        user.setLastLoginAt(T0.minus(Duration.ofDays(1)));

        assertThat(service.stateFor(USER).status()).isEqualTo(Status.TOO_SOON);
    }

    @Test
    void theInstantsAreRoundedUpToWholeSeconds() {
        Instant stamp = T0.minus(Duration.ofDays(1)).plusMillis(250);
        user.setPinResetRequestedAt(stamp);

        AccountRecoveryState state = service.stateFor(USER);

        assertThat(state.completableAtEpochSeconds()).isEqualTo(stamp.plus(WAIT).getEpochSecond() + 1);
    }

    @Test
    void theEpisodeLifeIsTheWaitPlusTheLongerOfTheWaitAndTheDormancy() {
        properties.getSecurity().setAccountRecoveryWait(Duration.ofDays(7));
        properties.getSecurity().setAccountRecoveryDormancy(Duration.ofDays(2));
        assertThat(properties.getSecurity().getAccountRecoveryEpisodeLife()).isEqualTo(Duration.ofDays(14));

        properties.getSecurity().setAccountRecoveryWait(Duration.ofDays(2));
        properties.getSecurity().setAccountRecoveryDormancy(Duration.ofDays(7));
        assertThat(properties.getSecurity().getAccountRecoveryEpisodeLife()).isEqualTo(Duration.ofDays(9));
    }

    // -------------------- start --------------------

    @Test
    void startingOnAnAvailableAccountStampsNowAndAuditsIt() {
        AccountRecoveryState state = service.start(USER, "••••4567", "203.0.113.9");

        assertThat(user.getPinResetRequestedAt()).isEqualTo(T0);
        assertThat(state.status()).isEqualTo(Status.PENDING);
        assertThat(state.completableAtEpochSeconds()).isEqualTo(T0.plus(WAIT).getEpochSecond());
        verify(auditLogger).accountRecoveryRequested(USER, "••••4567", "203.0.113.9");
        verify(repository, never()).findByUserId(USER);
    }

    @Test
    void startingAgainLeavesALiveEpisodeExactlyWhereItWas() {
        Instant openedAt = T0.minus(Duration.ofDays(2));
        user.setPinResetRequestedAt(openedAt);

        assertThat(service.start(USER, "••••4567", "203.0.113.9").status()).isEqualTo(Status.PENDING);
        clock.set(openedAt.plus(WAIT));
        assertThat(service.start(USER, "••••4567", "203.0.113.9").status()).isEqualTo(Status.READY);

        assertThat(user.getPinResetRequestedAt()).isEqualTo(openedAt);
        verify(auditLogger, never()).accountRecoveryRequested(any(), any(), any());
    }

    @Test
    void startingOverADeadEpisodeOpensAFreshOne() {
        user.setPinResetRequestedAt(T0.minus(Duration.ofDays(365)));

        assertThat(service.start(USER, "••••4567", "203.0.113.9").status()).isEqualTo(Status.PENDING);
        assertThat(user.getPinResetRequestedAt()).isEqualTo(T0);
    }

    @Test
    void startingOnARecentlyUsedAccountIsRefusedWithTheRoundedWaitAndWritesNothing() {
        user.setLastLoginAt(Instant.parse("2026-08-30T09:20:00Z"));
        long published = service.stateFor(USER).availableAtEpochSeconds();
        assertThat(published).isEqualTo(Instant.parse("2026-09-06T10:00:00Z").getEpochSecond());

        assertThatThrownBy(() -> service.start(USER, "••••4567", "203.0.113.9"))
                .isInstanceOf(AccountRecoveryCooldownException.class)
                .extracting(ex -> ((AccountRecoveryCooldownException) ex).getRemainingSeconds())
                .isEqualTo(published - T0.getEpochSecond());

        assertThat(user.getPinResetRequestedAt()).isNull();
        verify(auditLogger, never()).accountRecoveryRequested(any(), any(), any());
    }

    /** The retry-after under short testing durations points at the same whole minute that is published. */
    @Test
    void underShortTestingDurationsStartingTooSoonRetriesAtThePublishedMinute() {
        useShortTestingDurations();
        user.setLastLoginAt(Instant.parse("2026-09-01T10:14:20Z"));
        long published = service.stateFor(USER).availableAtEpochSeconds();
        assertThat(published).isEqualTo(Instant.parse("2026-09-01T10:18:00Z").getEpochSecond());

        assertThatThrownBy(() -> service.start(USER, "••••4567", "203.0.113.9"))
                .isInstanceOf(AccountRecoveryCooldownException.class)
                .extracting(ex -> ((AccountRecoveryCooldownException) ex).getRemainingSeconds())
                .isEqualTo(published - T0.getEpochSecond())
                .isEqualTo(150L);

        assertThat(user.getPinResetRequestedAt()).isNull();
    }

    @Test
    void startingForAnAccountWithNoRowCreatesTheRowUnderTheLock() {
        when(repository.findByUserIdForUpdate(USER)).thenReturn(Optional.empty());
        when(repository.saveAndFlush(any(IdentityUser.class))).thenAnswer(call -> call.getArgument(0));

        assertThat(service.start(USER, "••••4567", "203.0.113.9").status()).isEqualTo(Status.PENDING);
    }

    // -------------------- complete --------------------

    private void readyEpisode() {
        user.setPinResetRequestedAt(T0.minus(WAIT));
        user.setPinFailureCount(3);
        user.setPinLockedUntil(T0.plus(Duration.ofMinutes(10)));
    }

    @Test
    void completingAReadyEpisodeSetsThePinEndsTheEpisodeClearsTheLockAndRemovesThePasskeys() {
        readyEpisode();
        when(passkeyService.removeAllForUser(USER)).thenReturn(2);

        int removed = service.complete(USER, "739164");

        assertThat(removed).isEqualTo(2);
        assertThat(passwordEncoder.matches("739164", user.getPinHash())).isTrue();
        assertThat(user.getPinResetRequestedAt()).isNull();
        assertThat(user.getPinFailureCount()).isZero();
        assertThat(user.getPinLockedUntil()).isNull();
        // pin_set_at is stamped, so the fresh-factor hold keeps the recovered PIN off a phone change.
        assertThat(user.getPinSetAt()).isNotNull();
        verify(passkeyService).removeAllForUser(USER);
        verify(auditLogger).accountRecoveryCompleted(USER, 2);
    }

    /**
     * D5 must survive a login that cannot be finished after the commit, and the account must not
     * look dormant because the sign-in record after the commit never ran.
     */
    @Test
    void completingARecoveryRecordsTheOwedSignOutAndCountsAsActivity() {
        readyEpisode();
        user.setLastLoginAt(T0.minus(Duration.ofDays(30)));

        service.complete(USER, "739164");

        verify(endOtherSessionsService).markOwed(USER);
        assertThat(user.getLastLoginAt()).isEqualTo(T0);
        assertThat(service.stateFor(USER).status()).isEqualTo(Status.TOO_SOON);
    }

    @Test
    void completingAPendingEpisodeIsNotReadyAndChangesNothing() {
        user.setPinResetRequestedAt(T0.minus(WAIT).plusSeconds(1));

        assertThatThrownBy(() -> service.complete(USER, "739164"))
                .isInstanceOf(AccountRecoveryNotReadyException.class)
                .extracting(ex -> ((AccountRecoveryNotReadyException) ex).getState().status())
                .isEqualTo(Status.PENDING);

        assertThat(passwordEncoder.matches("482913", user.getPinHash())).isTrue();
        verifyNoInteractions(passkeyService, endOtherSessionsService);
    }

    @Test
    void completingAfterACancelOrWithoutAnEpisodeIsNotReady() {
        assertThatThrownBy(() -> service.complete(USER, "739164"))
                .isInstanceOf(AccountRecoveryNotReadyException.class)
                .extracting(ex -> ((AccountRecoveryNotReadyException) ex).getState().status())
                .isEqualTo(Status.AVAILABLE);

        when(repository.findByUserIdForUpdate(USER)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.complete(USER, "739164"))
                .isInstanceOf(AccountRecoveryNotReadyException.class);
        verifyNoInteractions(passkeyService);
    }

    @Test
    void completingAnExpiredEpisodeIsNotReady() {
        user.setPinResetRequestedAt(T0.minus(LIFE));

        assertThatThrownBy(() -> service.complete(USER, "739164"))
                .isInstanceOf(AccountRecoveryNotReadyException.class);
        verifyNoInteractions(passkeyService);
    }

    @Test
    void aMalformedOrWeakNewPinIsRefusedWithoutWritingOrCountingAnything() {
        readyEpisode();

        assertThatThrownBy(() -> service.complete(USER, "12ab")).isInstanceOf(InvalidPinException.class);
        assertThatThrownBy(() -> service.complete(USER, "123456")).isInstanceOf(WeakPinException.class);
        assertThatThrownBy(() -> service.complete(USER, null)).isInstanceOf(InvalidPinException.class);

        assertThat(passwordEncoder.matches("482913", user.getPinHash())).isTrue();
        assertThat(user.getPinResetRequestedAt()).isEqualTo(T0.minus(WAIT));
        assertThat(user.getPinFailureCount()).isEqualTo(3);
        verifyNoInteractions(passkeyService, endOtherSessionsService);
    }

    // -------------------- cancel --------------------

    @Test
    void theOwnersCancelEndsALiveEpisodeAndCountsAsActivity() {
        user.setPinResetRequestedAt(T0.minus(Duration.ofDays(1)));
        user.setLastLoginAt(T0.minus(Duration.ofDays(30)));

        assertThat(service.cancel(USER, "198.51.100.4")).isTrue();

        assertThat(user.getPinResetRequestedAt()).isNull();
        assertThat(user.getLastLoginAt()).isEqualTo(T0);
        verify(auditLogger).accountRecoveryCancelled(USER, "198.51.100.4");
        // E4: whoever started it cannot start another one the next minute.
        clock.set(T0.plusSeconds(60));
        assertThat(service.stateFor(USER).status()).isEqualTo(Status.TOO_SOON);
    }

    @Test
    void cancellingAReadyEpisodeAlsoEndsIt() {
        user.setPinResetRequestedAt(T0.minus(WAIT));

        assertThat(service.cancel(USER, "198.51.100.4")).isTrue();
        assertThatThrownBy(() -> service.complete(USER, "739164"))
                .isInstanceOf(AccountRecoveryNotReadyException.class);
    }

    @Test
    void cancellingWithNothingLiveChangesNothing() {
        user.setLastLoginAt(T0.minus(Duration.ofDays(30)));
        user.setPinResetRequestedAt(T0.minus(LIFE));

        assertThat(service.cancel(USER, "198.51.100.4")).isFalse();

        assertThat(user.getLastLoginAt()).isEqualTo(T0.minus(Duration.ofDays(30)));
        verify(auditLogger, never()).accountRecoveryCancelled(any(), any());

        when(repository.findByUserIdForUpdate(USER)).thenReturn(Optional.empty());
        assertThat(service.cancel(USER, "198.51.100.4")).isFalse();
    }

    // -------------------- the other cancel sources --------------------

    @Test
    void aSignInWithAFactorEndsTheEpisode() {
        user.setPinResetRequestedAt(T0.minus(Duration.ofDays(1)));
        UserSecurityService userSecurityService = userSecurityService();

        userSecurityService.recordSuccessfulLogin(USER);

        assertThat(user.getPinResetRequestedAt()).isNull();
        assertThat(user.getLastLoginAt()).isNotNull();
    }

    @Test
    void producingThePinEndsTheEpisode() {
        user.setPinResetRequestedAt(T0.minus(Duration.ofDays(1)));

        userSecurityService().validatePinOrThrow(USER, "482913");

        assertThat(user.getPinResetRequestedAt()).isNull();
    }

    // -------------------- the banner --------------------

    @Test
    void pendingForReportsOnlyALiveEpisode() {
        assertThat(service.pendingFor(USER)).isEmpty();

        user.setLastLoginAt(T0.minus(Duration.ofDays(1)));
        assertThat(service.pendingFor(USER)).isEmpty();

        user.setPinResetRequestedAt(T0.minus(Duration.ofDays(1)));
        assertThat(service.pendingFor(USER)).get().extracting(AccountRecoveryState::status).isEqualTo(Status.PENDING);

        user.setPinResetRequestedAt(T0.minus(WAIT));
        assertThat(service.pendingFor(USER)).get().extracting(AccountRecoveryState::status).isEqualTo(Status.READY);
    }

    private UserSecurityService userSecurityService() {
        return new UserSecurityService(repository, passwordEncoder, properties, mock(DirectoryService.class),
                mock(PhoneNumberHasher.class), mock(OtpService.class), auditLogger, mock(StringRedisTemplate.class),
                new PinPolicy());
    }

    /** A clock the test moves by hand. */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant instant) {
            this.now = instant;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
