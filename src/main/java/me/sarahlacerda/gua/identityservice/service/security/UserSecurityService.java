package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;
import java.time.Instant;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.exception.PinResetCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinResetNotRequestedException;
import me.sarahlacerda.gua.identityservice.exception.UnknownUserException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

@Service
@RequiredArgsConstructor
public class UserSecurityService {

    private static final String PIN_PATTERN = "\\d{6}";

    private final IdentityUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final IdentityServiceProperties properties;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final OtpService otpService;
    private final SecurityAuditLogger auditLogger;

    @Transactional
    public IdentityUser ensureUser(String userId) {
        return repository.findByUserId(userId)
            .orElseGet(() -> repository.save(IdentityUser.builder().userId(userId).build()));
    }

    @Transactional(readOnly = true)
    public IdentityUser requireExistingUser(String userId) {
        return repository.findByUserId(userId)
            .orElseThrow(() -> new UnknownUserException("Unknown user: " + userId));
    }

    @Transactional
    public void setInitialPin(String userId, String newPin) {
        IdentityUser user = ensureUser(userId);
        if (user.hasPin()) {
            throw new InvalidPinOperationException("PIN already set");
        }
        validatePinFormat(newPin);
        applyNewPin(user, newPin);
        auditLogger.pinInitialized(userId);
    }

    @Transactional
    public void updatePin(String userId, String currentPin, String newPin) {
        IdentityUser user = requireExistingUser(userId);
        if (!user.hasPin()) {
            throw new InvalidPinOperationException("No existing PIN to update");
        }
        validatePinFormat(newPin);
        if (!passwordEncoder.matches(currentPin, user.getPinHash())) {
            throw new InvalidPinException("Current PIN is incorrect");
        }
        applyNewPin(user, newPin);
        auditLogger.pinUpdated(userId);
    }

    @Transactional(readOnly = true)
    public boolean hasPin(String userId) {
        return repository.findByUserId(userId)
            .map(IdentityUser::hasPin)
            .orElse(false);
    }

    @Transactional(readOnly = true)
    public void validatePinOrThrow(String userId, String providedPin) {
        IdentityUser user = requireExistingUser(userId);
        if (!user.hasPin()) {
            throw new InvalidPinOperationException("PIN not set for user");
        }
        Instant now = Instant.now();

        if (user.getPinLockedUntil() != null) {
            if (now.isBefore(user.getPinLockedUntil())) {
                long remaining = Duration.between(now, user.getPinLockedUntil()).toSeconds();
                throw new PinLockedException("PIN locked due to repeated failures", remaining);
            }
            resetFailureTracking(user);
        }

        if (!StringUtils.hasText(providedPin) || !passwordEncoder.matches(providedPin, user.getPinHash())) {
            int failureCount = registerFailedAttempt(user, now, userId);
            auditLogger.pinValidationFailed(userId, failureCount);
            throw new InvalidPinException("Invalid PIN supplied");
        }

        resetFailureTracking(user);
        auditLogger.pinValidationSucceeded(userId);
    }

    @Transactional
    public void recordSuccessfulLogin(String userId) {
        IdentityUser user = ensureUser(userId);
        user.setLastLoginAt(Instant.now());
        resetFailureTracking(user);
    }

    @Transactional
    public void requestPinReset(String userId, String phone, String requesterIp) {
        IdentityUser user = requireExistingUser(userId);

        if (!user.hasPin()) {
            throw new InvalidPinOperationException("PIN not set for user");
        }

        Instant now = Instant.now();
        Duration cooldown = properties.getSecurity().getPinResetCooldown();
        Instant lastLogin = user.getLastLoginAt();
        if (lastLogin != null && Duration.between(lastLogin, now).compareTo(cooldown) < 0) {
            long remainingSeconds = cooldown.minus(Duration.between(lastLogin, now)).toSeconds();
            throw new PinResetCooldownException("PIN reset cooldown active", remainingSeconds);
        }
        ensurePhoneBelongsToUser(userId, phone);
        otpService.sendOtp(phone, requesterIp, null);
        user.setPinResetRequestedAt(now);
        auditLogger.pinResetRequested(userId, maskPhoneNumber(phone), requesterIp);
    }

    @Transactional
    public void completePinReset(String userId, String phone, String code, String newPin) {
        IdentityUser user = requireExistingUser(userId);
        if (user.getPinResetRequestedAt() == null) {
            throw new PinResetNotRequestedException("PIN reset not requested");
        }
        Duration cooldown = properties.getSecurity().getPinResetCooldown();
        if (Duration.between(user.getPinResetRequestedAt(), Instant.now()).compareTo(cooldown) < 0) {
            throw new PinResetCooldownException("PIN reset still cooling down", -1);
        }
        ensurePhoneBelongsToUser(userId, phone);
        otpService.verifyOtp(phone, code);
        validatePinFormat(newPin);
        applyNewPin(user, newPin);
        user.setPinResetRequestedAt(null);
        auditLogger.pinResetCompleted(userId);
    }

    private void ensurePhoneBelongsToUser(String userId, String phone) {
        String digest = phoneNumberHasher.digest(phone);
        directoryService.findByDigest(digest)
            .filter(entry -> entry.getUserId().equals(userId))
            .orElseThrow(() -> new InvalidPinOperationException("Phone number not linked to user"));
    }

    private void applyNewPin(IdentityUser user, String newPin) {
        user.setPinHash(passwordEncoder.encode(newPin));
        user.setPinSetAt(Instant.now());
        user.setPinResetRequestedAt(null);
        resetFailureTracking(user);
    }

    private void validatePinFormat(String pin) {
        if (!StringUtils.hasText(pin) || !pin.matches(PIN_PATTERN)) {
            throw new InvalidPinException("PIN must be a 6-digit numeric value");
        }
    }

    private int registerFailedAttempt(IdentityUser user, Instant now, String userId) {
        int failureCount = user.getPinFailureCount() + 1;
        user.setPinFailureCount(failureCount);
        int maxAttempts = properties.getSecurity().getMaxPinAttempts();
        if (failureCount >= maxAttempts) {
            Instant lockedUntil = now.plus(properties.getSecurity().getPinLockDuration());
            user.setPinLockedUntil(lockedUntil);
            user.setPinFailureCount(0);
            auditLogger.pinLocked(userId, lockedUntil);
            return maxAttempts;
        }
        return failureCount;
    }

    private void resetFailureTracking(IdentityUser user) {
        user.setPinFailureCount(0);
        user.setPinLockedUntil(null);
    }

    private String maskPhoneNumber(String phone) {
        if (!StringUtils.hasText(phone) || phone.length() < 4) {
            return "***";
        }
        String lastFour = phone.substring(phone.length() - 4);
        return "***" + lastFour;
    }
}
