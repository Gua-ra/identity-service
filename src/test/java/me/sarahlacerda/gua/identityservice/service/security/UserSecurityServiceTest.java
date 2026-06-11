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
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
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
        doNothing().when(otpService).sendOtp("+12025550123", "127.0.0.1", null);

        service.requestPinReset("@user:gua.global", "+12025550123", "127.0.0.1");

        verify(otpService).sendOtp("+12025550123", "127.0.0.1", null);
        verify(auditLogger).pinResetRequested(eq("@user:gua.global"), any(String.class), eq("127.0.0.1"));
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

        verify(otpService).verifyOtp("+12025550123", "876543");
        verify(auditLogger).pinResetCompleted("@user:gua.global");
        assertThat(passwordEncoder.matches("284917", user.getPinHash())).isTrue();
        assertThat(user.getPinResetRequestedAt()).isNull();
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
    void startPinChangeRejectsWhenWithinCooldown() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));
        user.setLastPinChangeAt(Instant.now().minus(Duration.ofHours(1)));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.startPinChange("@user:gua.global", "+12025550123", "123456", "127.0.0.1"))
                .isInstanceOf(PinChangeCooldownException.class);
    }

    @Test
    void startPinChangeRejectsWrongCurrentPin() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));
        when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(directoryEntry("@user:gua.global")));

        assertThatThrownBy(() -> service.startPinChange("@user:gua.global", "+12025550123", "000000", "127.0.0.1"))
                .isInstanceOf(InvalidPinException.class);
        verify(otpService, org.mockito.Mockito.never()).sendOtp(any(), any(), any());
    }

    @Test
    void startPinChangeSendsOtpAndPersistsChallenge() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(repository.findByUserIdForUpdate("@user:gua.global")).thenReturn(Optional.of(user));
        when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(directoryEntry("@user:gua.global")));

        String challengeId = service.startPinChange("@user:gua.global", "+12025550123", "123456", "127.0.0.1");

        assertThat(challengeId).isNotBlank();
        verify(otpService).sendOtp("+12025550123", "127.0.0.1", null);
        verify(valueOps).set(eq("pin:change:" + challengeId), eq("@user:gua.global|+12025550123"),
                eq(Duration.ofMinutes(5)));
        verify(auditLogger).pinChangeStarted(eq("@user:gua.global"), any(String.class), eq("127.0.0.1"));
    }

    @Test
    void completePinChangeAppliesNewPinAndStampsTimestamp() {
        IdentityUser user = IdentityUser.builder().userId("@user:gua.global").build();
        user.setPinHash(passwordEncoder.encode("123456"));

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));
        when(valueOps.get("pin:change:chal-1")).thenReturn("@user:gua.global|+12025550123");

        service.completePinChange("@user:gua.global", "chal-1", "876543", "284917");

        verify(otpService).verifyOtp("+12025550123", "876543");
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
    }
}
