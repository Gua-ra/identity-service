package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeChallengeNotFoundException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
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

    // -------------------- what ends a pending recovery episode --------------------

    @Test
    void provingThePinEndsAPendingRecovery() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setPinResetRequestedAt(Instant.now().minus(Duration.ofDays(8)));

        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));

        service.validatePinOrThrow("@user:gua.global", "123456");

        // Somebody who can produce the PIN is not the person locked out of it, and a recovery
        // left running would hand the account to whoever started it once the wait was over.
        assertThat(user.getPinResetRequestedAt()).isNull();
    }

    @Test
    void aWrongPinLeavesAPendingRecoveryExactlyWhereItWas() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        Instant openedAt = Instant.now().minus(Duration.ofDays(3));
        user.setPinResetRequestedAt(openedAt);

        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.validatePinOrThrow("@user:gua.global", "000000"))
                .isInstanceOf(InvalidPinException.class);

        // Guessing at the PIN is not proof of anything, so it must not be able to cancel a
        // recovery that is in progress.
        assertThat(user.getPinResetRequestedAt()).isEqualTo(openedAt);
    }

    @Test
    void aFinishedSignInEndsAPendingRecoveryUnderTheRowLock() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setPinResetRequestedAt(Instant.now().minus(Duration.ofDays(3)));

        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));

        service.recordSuccessfulLogin("@user:gua.global");

        // Only a finished sign-in reaches here, so the person produced a factor and is not the
        // one locked out. Read under the lock, so the write cannot put back a PIN hash or a
        // stamp a concurrent recovery completion or cancel had just committed.
        assertThat(user.getPinResetRequestedAt()).isNull();
        assertThat(user.getLastLoginAt()).isNotNull();
        verify(repository, org.mockito.Mockito.never()).findByUserId("@user:gua.global");
    }

    @Test
    void recordingASignInCreatesTheRowForAnAccountThatNeverHadOne() {
        when(repository.findByUserIdForUpdate("@new:gua.global")).thenReturn(Optional.empty());
        when(repository.save(any(IdentityUser.class))).thenAnswer(call -> call.getArgument(0));

        service.recordSuccessfulLogin("@new:gua.global");

        org.mockito.ArgumentCaptor<IdentityUser> saved = org.mockito.ArgumentCaptor.forClass(IdentityUser.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getUserId()).isEqualTo("@new:gua.global");
        assertThat(saved.getValue().getLastLoginAt()).isNotNull();
    }

    @Test
    void settingTheFirstPinReadsTheRowUnderTheLock() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));

        service.setInitialPin("@user:gua.global", "284917");

        assertThat(passwordEncoder.matches("284917", user.getPinHash())).isTrue();
        verify(auditLogger).pinInitialized("@user:gua.global");
        verify(repository, org.mockito.Mockito.never()).findByUserId("@user:gua.global");
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
        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));

        // Created.
        service.setInitialPin("@user:gua.global", "284917");
        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isPositive();

        // Changed: the hold reopens rather than carrying the old PIN's age forward.
        user.setPinSetAt(Instant.now().minus(Duration.ofDays(30)));
        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isZero();
        service.updatePin("@user:gua.global", "284917", "391748");
        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isPositive();

        // Recovered: a PIN chosen by an account recovery is exactly as new as any other.
        user.setPinSetAt(Instant.now().minus(Duration.ofDays(30)));
        user.setPinResetRequestedAt(Instant.now().minus(Duration.ofDays(8)));
        service.applyRecoveredPin(user, "509382");
        assertThat(service.changePhonePinHoldRemainingSeconds("@user:gua.global")).isPositive();
        assertThat(user.getPinResetRequestedAt()).isNull();
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
