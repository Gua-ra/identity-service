package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
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
import me.sarahlacerda.gua.identityservice.exception.PhoneChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeChallengeNotFoundException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException;
import me.sarahlacerda.gua.identityservice.exception.UnknownUserException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpScope;
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
        setInitialPin(lockOrCreateUser(userId), newPin);
    }

    /** The caller must already hold the row lock. */
    void setInitialPin(IdentityUser user, String newPin) {
        if (user.hasPin()) {
            throw new InvalidPinOperationException("PIN already set");
        }
        validatePinFormat(newPin);
        applyNewPin(user, newPin);
        auditLogger.pinInitialized(user.getUserId());
    }

    @Transactional
    public void updatePin(String userId, String currentPin, String newPin) {
        IdentityUser user = requireLockedUser(userId);
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

    void preparePinChange(String userId, String phone) {
        IdentityUser user = requireExistingUser(userId);
        if (!user.hasPin()) {
            throw new InvalidPinOperationException("PIN not set for user");
        }
        enforcePinChangeCooldown(user);
        ensurePhoneBelongsToUser(userId, phone);
    }

    /** Authorizes nothing: only PinChangeService may call it, after preparePinChange and an accepted factor. */
    String issuePinChangeChallenge(String userId, String phone, String requesterIp) {
        String challengeId = UUID.randomUUID().toString();
        otpService.sendScopedOtp(OtpScope.PIN_CHANGE, challengeId, phone, requesterIp, null);

        Duration ttl = properties.getSecurity().getPinChangeChallengeTtl();
        redisTemplate.opsForValue().set(changeChallengeKey(challengeId), userId + "|" + phone, ttl);
        auditLogger.pinChangeStarted(userId, maskPhoneNumber(phone), requesterIp);
        return challengeId;
    }

    @Transactional
    public void completePinChange(String userId, String challengeId, String otpCode, String newPin) {
        IdentityUser user = requireLockedUser(userId);
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
            otpService.discardScopedOtp(OtpScope.PIN_CHANGE, challengeId);
            throw new PinChangeChallengeNotFoundException("PIN change challenge does not belong to caller");
        }
        otpService.verifyScopedOtp(OtpScope.PIN_CHANGE, challengeId, otpCode);
        validatePinFormat(newPin);
        applyNewPin(user, newPin);
        user.setLastPinChangeAt(Instant.now());
        redisTemplate.delete(key);
        auditLogger.pinChangeCompleted(userId);
    }

    @Transactional(readOnly = true)
    public void enforcePhoneChangeCooldown(String userId) {
        IdentityUser user = requireExistingUser(userId);
        Instant lastChange = user.getLastPhoneChangeAt();
        if (lastChange == null) {
            return;
        }
        Duration cooldown = properties.getSecurity().getPhoneChangeCooldown();
        Duration since = Duration.between(lastChange, Instant.now());
        if (since.compareTo(cooldown) < 0) {
            long remaining = cooldown.minus(since).toSeconds();
            throw new PhoneChangeCooldownException("Phone change cooldown active", remaining);
        }
    }

    // A freshly set PIN cannot be the phone-change step-up until identity.security.pin-reset-cooldown passes.
    // Returns 0 when nothing is held.
    @Transactional(readOnly = true)
    public long changePhonePinHoldRemainingSeconds(String userId) {
        return repository.findByUserId(userId)
                .map(this::pinHoldRemainingSeconds)
                .orElse(0L);
    }

    @Transactional(readOnly = true)
    public void enforcePhoneChangePinHold(String userId) {
        long remaining = changePhonePinHoldRemainingSeconds(userId);
        if (remaining > 0) {
            throw new TwoFactorCooldownException(
                    "Two-step verification was set up too recently to change the phone number", remaining);
        }
    }

    /** Takes the instant, not the account: this service must not decide anything from what else an account holds. */
    public void enforceFreshFactorHold(Instant factorCreatedAt) {
        long remaining = freshFactorHoldRemainingSeconds(factorCreatedAt);
        if (remaining > 0) {
            throw new TwoFactorCooldownException(
                    "Two-step verification was set up too recently to authorize this change", remaining);
        }
    }

    private long pinHoldRemainingSeconds(IdentityUser user) {
        if (!user.hasPin()) {
            return 0L;
        }
        return freshFactorHoldRemainingSeconds(user.getPinSetAt());
    }

    private long freshFactorHoldRemainingSeconds(Instant factorCreatedAt) {
        if (factorCreatedAt == null) {
            // No stamp: the row predates the column, so the factor is not new.
            return 0L;
        }
        Duration hold = properties.getSecurity().getPinResetCooldown();
        Duration since = Duration.between(factorCreatedAt, Instant.now());
        if (since.isNegative()) {
            // Clock skew put the stamp in the future: hold for the whole window.
            return hold.toSeconds();
        }
        if (since.compareTo(hold) >= 0) {
            return 0L;
        }
        // Never round a live hold down to zero, which would read as "no hold".
        return Math.max(hold.minus(since).toSeconds(), 1L);
    }

    /** Runs inside the swap transaction and locks the row like every other writer. */
    @Transactional
    public void stampPhoneChange(String userId) {
        IdentityUser user = lockOrCreateUser(userId);
        user.setLastPhoneChangeAt(Instant.now());
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
        // Producing the PIN ends any pending account recovery.
        user.setPinResetRequestedAt(null);
        auditLogger.pinValidationSucceeded(userId);
    }

    @Transactional
    public void recordSuccessfulLogin(String userId) {
        // Locked, because this write races the recovery writers.
        IdentityUser user = lockOrCreateUser(userId);
        user.setLastLoginAt(Instant.now());
        resetFailureTracking(user);
        // A completed sign-in ends any pending recovery episode.
        user.setPinResetRequestedAt(null);
    }

    /** Reads the account row without locking it, for status answers that write nothing. */
    Optional<IdentityUser> findUser(String userId) {
        return repository.findByUserId(userId);
    }

    Optional<IdentityUser> lockUser(String userId) {
        return repository.findByUserIdForUpdate(userId);
    }

    /** The insert is flushed at once, so two transactions creating the same row meet on the user_id unique index. */
    IdentityUser lockOrCreateUser(String userId) {
        return repository.findByUserIdForUpdate(userId)
                .orElseGet(() -> repository.saveAndFlush(IdentityUser.builder().userId(userId).build()));
    }

    private IdentityUser requireLockedUser(String userId) {
        return repository.findByUserIdForUpdate(userId)
                .orElseThrow(() -> new UnknownUserException("Unknown user: " + userId));
    }

    /** The stamp is pin_reset_requested_at. */
    void openRecoveryEpisode(IdentityUser user, Instant requestedAt) {
        user.setPinResetRequestedAt(requestedAt);
    }

    void endRecoveryEpisode(IdentityUser user) {
        user.setPinResetRequestedAt(null);
    }

    void recordAccountActivity(IdentityUser user, Instant at) {
        user.setLastLoginAt(at);
    }

    void validateNewPin(String newPin) {
        validatePinFormat(newPin);
    }

    /** Stamps pin_set_at so the fresh-factor hold applies to a recovered PIN. */
    void applyRecoveredPin(IdentityUser user, String newPin) {
        validatePinFormat(newPin);
        applyNewPin(user, newPin);
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
