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
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.exception.PinResetCooldownException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

class UserSecurityServiceTest {

    private IdentityUserRepository repository;
    private PasswordEncoder passwordEncoder;
    private IdentityServiceProperties properties;
    private DirectoryService directoryService;
    private PhoneNumberHasher phoneNumberHasher;
    private OtpService otpService;
    private SecurityAuditLogger auditLogger;
    private UserSecurityService service;

    @BeforeEach
    void setUp() {
        repository = mock(IdentityUserRepository.class);
        passwordEncoder = new BCryptPasswordEncoder();
        properties = new IdentityServiceProperties();
        properties.getSecurity().setPinResetCooldown(Duration.ofDays(7));
        properties.getSecurity().setPinLockDuration(Duration.ofMinutes(5));
        properties.getSecurity().setMaxPinAttempts(3);
        directoryService = mock(DirectoryService.class);
        phoneNumberHasher = mock(PhoneNumberHasher.class);
        otpService = mock(OtpService.class);
        auditLogger = mock(SecurityAuditLogger.class);
        service = new UserSecurityService(repository, passwordEncoder, properties, directoryService, phoneNumberHasher, otpService, auditLogger);
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

        when(repository.findByUserId("@user:gua.global")).thenReturn(Optional.of(user));

        for (int i = 0; i < properties.getSecurity().getMaxPinAttempts(); i++) {
            assertThatThrownBy(() -> service.validatePinOrThrow("@user:gua.global", "000000"))
                .isInstanceOf(InvalidPinException.class);
        }

        assertThatThrownBy(() -> service.validatePinOrThrow("@user:gua.global", "123456"))
            .isInstanceOf(PinLockedException.class);

        verify(auditLogger, times(properties.getSecurity().getMaxPinAttempts())).pinValidationFailed(eq("@user:gua.global"), any(Integer.class));
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

        service.completePinReset("@user:gua.global", "+12025550123", "876543", "111111");

        verify(otpService).verifyOtp("+12025550123", "876543");
        verify(auditLogger).pinResetCompleted("@user:gua.global");
        assertThat(passwordEncoder.matches("111111", user.getPinHash())).isTrue();
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
}
