package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeChallengeNotFoundException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.exception.PinResetCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinResetNotRequestedException;
import me.sarahlacerda.gua.identityservice.exception.PinSetupRequiredException;
import me.sarahlacerda.gua.identityservice.exception.UnknownUserException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

@Service
@RequiredArgsConstructor
public class UserSecurityService {

    private static final String CHANGE_CHALLENGE_KEY_PREFIX = "pin:change:";

    private final IdentityUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final IdentityServiceProperties properties;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final OtpService otpService;
    private final SecurityAuditLogger auditLogger;
    private final StringRedisTemplate redisTemplate;
    private final PinPolicy pinPolicy;

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
        user.setLastPinChangeAt(Instant.now());
        auditLogger.pinUpdated(userId);
    }

    /**
     * Step 1 of the OTP-protected PIN change: verify the current PIN, enforce the
     * change cooldown, and send an
     * OTP to the verified phone. Returns an opaque challenge that the caller must
     * redeem in step 2.
     */
    @Transactional
    public String startPinChange(String userId, String phone, String currentPin, String requesterIp) {
        IdentityUser user = requireExistingUser(userId);
        if (!user.hasPin()) {
            throw new InvalidPinOperationException("PIN not set for user");
        }
        enforcePinChangeCooldown(user);
        ensurePhoneBelongsToUser(userId, phone);
        validatePinOrThrow(userId, currentPin);
        otpService.sendOtp(phone, requesterIp, null);

        String challengeId = UUID.randomUUID().toString();
        Duration ttl = properties.getSecurity().getPinChangeChallengeTtl();
        redisTemplate.opsForValue().set(changeChallengeKey(challengeId), userId + "|" + phone, ttl);
        auditLogger.pinChangeStarted(userId, maskPhoneNumber(phone), requesterIp);
        return challengeId;
    }

    /**
     * Step 2 of the OTP-protected PIN change: redeem the challenge with the OTP and
     * the new PIN.
     */
    @Transactional
    public void completePinChange(String userId, String challengeId, String otpCode, String newPin) {
        IdentityUser user = requireExistingUser(userId);
        if (!user.hasPin()) {
            throw new InvalidPinOperationException("PIN not set for user");
        }
        enforcePinChangeCooldown(user);

        String key = changeChallengeKey(challengeId);
        String stored = redisTemplate.opsForValue().get(key);
        if (!StringUtils.hasText(stored)) {
            throw new PinChangeChallengeNotFoundException("PIN change challenge missing or expired");
        }
        String[] parts = stored.split("\\|", 2);
        if (parts.length != 2 || !parts[0].equals(userId)) {
            redisTemplate.delete(key);
            throw new PinChangeChallengeNotFoundException("PIN change challenge does not belong to caller");
        }
        String phone = parts[1];
        otpService.verifyOtp(phone, otpCode);
        validatePinFormat(newPin);
        applyNewPin(user, newPin);
        user.setLastPinChangeAt(Instant.now());
        redisTemplate.delete(key);
        auditLogger.pinChangeCompleted(userId);
    }

    private void enforcePinChangeCooldown(IdentityUser user) {
        Instant lastChange = user.getLastPinChangeAt();
        if (lastChange == null) {
            return;
        }
        Duration cooldown = properties.getSecurity().getPinChangeCooldown();
        Instant now = Instant.now();
        Duration since = Duration.between(lastChange, now);
        if (since.compareTo(cooldown) < 0) {
            long remaining = cooldown.minus(since).toSeconds();
            throw new PinChangeCooldownException("PIN change cooldown active", remaining);
        }
    }

    private String changeChallengeKey(String challengeId) {
        return CHANGE_CHALLENGE_KEY_PREFIX + challengeId;
    }

    @Transactional(readOnly = true)
    public boolean hasPin(String userId) {
        return repository.findByUserId(userId)
                .map(IdentityUser::hasPin)
                .orElse(false);
    }

    /**
     * Seconds remaining on the post-PIN-write cooldown that gates using the PIN to step up a
     * change-phone request. The PIN's last-write timestamp ({@code pinSetAt}, stamped on
     * create/change/reset) plus the configurable window defines when the PIN becomes trusted.
     * Returns 0 when the user has no PIN, has never written one, or the window has elapsed.
     */
    @Transactional(readOnly = true)
    public long changePhoneCooldownRemainingSeconds(String userId) {
        return repository.findByUserId(userId)
                .map(this::computeChangePhoneCooldownRemaining)
                .orElse(0L);
    }

    private long computeChangePhoneCooldownRemaining(IdentityUser user) {
        if (!user.hasPin() || user.getPinSetAt() == null) {
            return 0L;
        }
        Duration window = properties.getSecurity().getChangePhone2faCooldown();
        Duration elapsed = Duration.between(user.getPinSetAt(), Instant.now());
        long remaining = window.minus(elapsed).toSeconds();
        return Math.max(0L, remaining);
    }

    /**
     * PIN validation for the change-phone step-up. Behaves like
     * {@link #validatePinOrThrow(String, String)} but distinguishes the "user has no PIN yet"
     * case: it raises {@link PinSetupRequiredException} (mapped to {@code pin_setup_required})
     * instead of the generic {@code pin_error}, so the client can route to PIN setup rather
     * than show an invalid-PIN error. A wrong PIN still surfaces as {@code invalid_pin}.
     */
    @Transactional(noRollbackFor = { InvalidPinException.class, PinLockedException.class })
    public void validatePinForReauthOrThrow(String userId, String providedPin) {
        if (!hasPin(userId)) {
            throw new PinSetupRequiredException("PIN not set for user");
        }
        validatePinOrThrow(userId, providedPin);
    }

    @Transactional(noRollbackFor = { InvalidPinException.class, PinLockedException.class })
    public void validatePinOrThrow(String userId, String providedPin) {
        IdentityUser user = repository.findByUserIdForUpdate(userId)
                .orElseThrow(() -> new UnknownUserException("Unknown user: " + userId));
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
        pinPolicy.validate(pin);
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
