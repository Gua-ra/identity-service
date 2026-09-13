package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeChallengeNotFoundException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.exception.PinResetCooldownException;
import me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpScope;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

class UserSecurityServiceTest {

    private IdentityUserRepository repository;
    private PasswordEncoder passwordEncoder;
    private IdentityServiceProperties properties;
    private DirectoryService directoryService;
    private PhoneNumberHasher phoneNumberHasher;
    private OtpService otpService;
    private SecurityAuditLogger auditLogger;
    private StringRedisTemplate redisTemplate;
    @SuppressWarnings("unchecked")
    private ValueOperations<String, String> valueOps;
    private UserSecurityService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        repository = mock(IdentityUserRepository.class);
        passwordEncoder = new BCryptPasswordEncoder();
        properties = new IdentityServiceProperties();
        properties.getSecurity().setPinResetCooldown(Duration.ofDays(7));
        properties.getSecurity().setPinLockDuration(Duration.ofMinutes(5));
        properties.getSecurity().setMaxPinAttempts(3);
        properties.getSecurity().setPinChangeCooldown(Duration.ofHours(24));
        properties.getSecurity().setPinChangeChallengeTtl(Duration.ofMinutes(5));
        directoryService = mock(DirectoryService.class);
        phoneNumberHasher = mock(PhoneNumberHasher.class);
        otpService = mock(OtpService.class);
        auditLogger = mock(SecurityAuditLogger.class);
        redisTemplate = mock(StringRedisTemplate.class);
        valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        service = new UserSecurityService(repository, passwordEncoder, properties, directoryService, phoneNumberHasher,
                otpService, auditLogger, redisTemplate, new PinPolicy());
    }

    @Test
    void requestPinResetFailsWithinCooldown() {
        IdentityUser user = IdentityUser.builder()
                .userId("@user:gua.global")
                .build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setLastLoginAt(Instant.now().minus(Duration.ofDays(2)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.requestPinReset("@user:gua.global", "+12025550123", "127.0.0.1"))
                .isInstanceOf(PinResetCooldownException.class);
    }

    @Test
    void validatePinLocksAfterRepeatedFailures() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));

        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));

        for (int i = 0; i < properties.getSecurity().getMaxPinAttempts(); i++) {
            assertThatThrownBy(() -> service.validatePinOrThrow("@user:gua.global", "000000"))
                    .isInstanceOf(InvalidPinException.class);
        }

        assertThatThrownBy(() -> service.validatePinOrThrow("@user:gua.global", "123456"))
                .isInstanceOf(PinLockedException.class);

        verify(auditLogger, times(properties.getSecurity().getMaxPinAttempts()))
                .pinValidationFailed(eq("@user:gua.global"), any(Integer.class));
        verify(auditLogger).pinLocked(eq("@user:gua.global"), any(Instant.class));
    }

    @Test
    void requestPinResetSendsOtpAfterCooldown() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setLastLoginAt(Instant.now().minus(Duration.ofDays(8)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(directoryEntry("@user:gua.global")));
        doNothing().when(otpService)
                .sendScopedOtp(OtpScope.PIN_RESET, "@user:gua.global", "+12025550123", "127.0.0.1", null);

        service.requestPinReset("@user:gua.global", "+12025550123", "127.0.0.1");

        // Keyed to the account, not to the phone, so the unauthenticated public send cannot
        // put a code where this flow looks for one.
        verify(otpService).sendScopedOtp(OtpScope.PIN_RESET, "@user:gua.global", "+12025550123", "127.0.0.1", null);
        verify(otpService, org.mockito.Mockito.never()).sendOtp(any(), any(), any());
        verify(auditLogger).pinResetRequested(eq("@user:gua.global"), any(String.class), eq("127.0.0.1"));
        assertThat(user.getPinResetRequestedAt()).isNotNull();
    }

    @Test
    void requestPinResetLeavesTheStampAloneOnARepeatRequest() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setLastLoginAt(Instant.now().minus(Duration.ofDays(30)));
        Instant openedAt = Instant.now().minus(Duration.ofDays(9));
        user.setPinResetRequestedAt(openedAt);

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(directoryEntry("@user:gua.global")));

        service.requestPinReset("@user:gua.global", "+12025550123", "127.0.0.1");

        // A second request re-sends the code so the reset stays completable once the wait is
        // over, and does NOT restart the wait. Restarting it would put completion permanently
        // out of reach, because the code that completes the reset lives for minutes and the
        // wait runs for days.
        verify(otpService).sendScopedOtp(OtpScope.PIN_RESET, "@user:gua.global", "+12025550123", "127.0.0.1", null);
        assertThat(user.getPinResetRequestedAt()).isEqualTo(openedAt);
    }

    @Test
    void completePinResetUpdatesPinAndClearsState() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setPinResetRequestedAt(Instant.now().minus(Duration.ofDays(8)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(directoryEntry("@user:gua.global")));

        service.completePinReset("@user:gua.global", "+12025550123", "876543", "284917");

        verify(otpService).verifyScopedOtp(OtpScope.PIN_RESET, "@user:gua.global", "876543");
        verify(otpService, org.mockito.Mockito.never()).verifyOtp(any(), any());
        verify(auditLogger).pinResetCompleted("@user:gua.global");
        assertThat(passwordEncoder.matches("284917", user.getPinHash())).isTrue();
        assertThat(user.getPinResetRequestedAt()).isNull();
    }

    // -------------------- what ends a pending reset episode --------------------

    @Test
    void aResetNobodyFinishedStopsSatisfyingTheWaitingPeriod() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setLastLoginAt(Instant.now().minus(Duration.ofDays(40)));
        // Asked for a year ago and walked away from. Nothing since: no login, no PIN check.
        user.setPinResetRequestedAt(Instant.now().minus(Duration.ofDays(365)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(directoryEntry("@user:gua.global")));

        service.requestPinReset("@user:gua.global", "+12025550123", "127.0.0.1");

        // That episode is long over, so this request opens a new one and the account holder
        // gets the whole waiting period to see the SMS and intervene. Left in place, the old
        // stamp would have satisfied the wait for ever: request and complete could then run
        // in the same minute, which is the seven days collapsing to nothing for exactly the
        // accounts nobody is watching.
        assertThat(user.getPinResetRequestedAt()).isAfter(Instant.now().minus(Duration.ofMinutes(1)));

        assertThatThrownBy(
                () -> service.completePinReset("@user:gua.global", "+12025550123", "876543", "284917"))
                .isInstanceOf(PinResetCooldownException.class);
        verify(otpService, org.mockito.Mockito.never()).verifyScopedOtp(any(), any(), any());
        assertThat(passwordEncoder.matches("284917", user.getPinHash())).isFalse();
    }

    @Test
    void provingThePinEndsAPendingReset() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setPinResetRequestedAt(Instant.now().minus(Duration.ofDays(8)));

        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));

        service.validatePinOrThrow("@user:gua.global", "123456");

        // Somebody who can produce the PIN is not waiting on a reset of it, and a stamp left
        // behind would keep the waiting period permanently satisfied for whoever comes next.
        assertThat(user.getPinResetRequestedAt()).isNull();
    }

    @Test
    void aWrongPinLeavesAPendingResetExactlyWhereItWas() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        Instant openedAt = Instant.now().minus(Duration.ofDays(3));
        user.setPinResetRequestedAt(openedAt);

        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.validatePinOrThrow("@user:gua.global", "000000"))
                .isInstanceOf(InvalidPinException.class);

        // Guessing at the PIN is not proof of anything, so it must not be able to shorten or
        // cancel a reset the account holder is waiting on.
        assertThat(user.getPinResetRequestedAt()).isEqualTo(openedAt);
    }

    @Test
    void aFinishedSignInEndsAPendingReset() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setPinResetRequestedAt(Instant.now().minus(Duration.ofDays(3)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));

        service.recordSuccessfulLogin("@user:gua.global");

        // Only a finished sign-in reaches here, so the person is not the one locked out of the
        // factor the reset would give back. It costs a live reset nothing the dormancy gate in
        // requestPinReset was not already costing it.
        assertThat(user.getPinResetRequestedAt()).isNull();
        assertThat(user.getLastLoginAt()).isNotNull();
    }

    private DirectoryEntry directoryEntry(String userId) {
        DirectoryEntry entry = DirectoryEntry.builder()
                .phoneDigest("digest")
                .userId(userId)
                .displayName("User")
                .build();
        return entry;
    }

    @Test
    void completePinChangeAppliesNewPinAndStampsTimestamp() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(valueOps.get("pin:change:chal-1")).thenReturn("@user:gua.global|+12025550123");

        service.completePinChange("@user:gua.global", "chal-1", "876543", "284917");

        verify(otpService).verifyScopedOtp(OtpScope.PIN_CHANGE, "chal-1", "876543");
        verify(otpService, org.mockito.Mockito.never()).verifyOtp(any(), any());
        verify(redisTemplate).delete("pin:change:chal-1");
        verify(auditLogger).pinChangeCompleted("@user:gua.global");
        assertThat(passwordEncoder.matches("284917", user.getPinHash())).isTrue();
        assertThat(user.getLastPinChangeAt()).isNotNull();
    }

    @Test
    void completePinChangeFailsWithUnknownChallenge() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(valueOps.get("pin:change:chal-1")).thenReturn(null);

        assertThatThrownBy(() -> service.completePinChange("@user:gua.global", "chal-1", "876543", "654321"))
                .isInstanceOf(PinChangeChallengeNotFoundException.class);
    }

    @Test
    void completePinChangeRejectsChallengeBelongingToAnotherUser() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(valueOps.get("pin:change:chal-1")).thenReturn("@someone-else:gua.global|+12025550123");

        assertThatThrownBy(() -> service.completePinChange("@user:gua.global", "chal-1", "876543", "654321"))
                .isInstanceOf(PinChangeChallengeNotFoundException.class);
        verify(redisTemplate).delete("pin:change:chal-1");
        // The code that belonged to the challenge goes with it.
        verify(otpService).discardScopedOtp(OtpScope.PIN_CHANGE, "chal-1");
    }

    // -------------------- fresh-2FA hold on changing the phone number --------------------

    @Test
    void aPinMintedMomentsAgoIsHeldFromBeingSpentOnAPhoneChange() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setPinSetAt(Instant.now().minus(Duration.ofMinutes(1)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));

        long remaining = service.changePhonePinHoldRemainingSeconds("@user:gua.global");

        assertThat(remaining).isGreaterThan(Duration.ofDays(6).toSeconds());
        assertThat(remaining).isLessThanOrEqualTo(Duration.ofDays(7).toSeconds());
        assertThatThrownBy(() -> service.enforcePhoneChangePinHold("@user:gua.global"))
                .isInstanceOf(TwoFactorCooldownException.class);
    }

    @Test
    void aPinOlderThanTheWindowIsNotHeld() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setPinSetAt(Instant.now().minus(Duration.ofDays(8)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));

        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isZero();
        service.enforcePhoneChangePinHold("@user:gua.global");
    }

    @Test
    void anAccountWithNoPinAndAnAccountWithNoRowAreNotHeld() {
        IdentityUser pinless = IdentityUser.builder().userId("@user:gua.global").build();
        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(pinless));
        when(repository.findByUserId("@ghost:gua.global")).thenReturn(Optional.empty());

        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isZero();
        assertThat(service.changePhonePinHoldRemainingSeconds("@ghost:gua.global")).isZero();
    }

    @Test
    void everyPathThatMintsAPinReopensTheHold() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(repository.save(any(IdentityUser.class))).thenAnswer(call -> call.getArgument(0));

        // Created.
        service.setInitialPin("@user:gua.global", "284917");
        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isPositive();

        // Changed: the hold reopens rather than carrying the old PIN's age forward.
        user.setPinSetAt(Instant.now().minus(Duration.ofDays(30)));
        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isZero();
        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));
        service.updatePin("@user:gua.global", "284917", "391748");
        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isPositive();

        // Reset.
        user.setPinSetAt(Instant.now().minus(Duration.ofDays(30)));
        user.setPinResetRequestedAt(Instant.now().minus(Duration.ofDays(8)));
        when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(directoryEntry("@user:gua.global")));
        service.completePinReset("@user:gua.global", "+12025550123", "876543", "509382");
        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isPositive();
    }

    @Test
    void theHoldReadsTheConfiguredWindowRatherThanAConstant() {
        properties.getSecurity().setPinResetCooldown(Duration.ofHours(1));
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setPinSetAt(Instant.now().minus(Duration.ofMinutes(50)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));

        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global"))
                .isBetween(1L, Duration.ofMinutes(10).toSeconds());
    }
}
