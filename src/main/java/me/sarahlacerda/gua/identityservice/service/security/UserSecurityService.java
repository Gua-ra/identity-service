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

    /**
     * Sets the first PIN on a row the caller has already locked. Package-private for the enrollment
     * step of the login flow, which weighs what else the account holds under the same lock.
     */
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

    /**
     * Step 1 of the OTP-protected PIN change, first half: the account has a PIN, the change
     * cooldown has passed, and the number belongs to the caller. {@link PinChangeService} runs it
     * before weighing the factor that authorizes the change, so a refusal here spends nothing.
     */
    void preparePinChange(String userId, String phone) {
        IdentityUser user = requireExistingUser(userId);
        if (!user.hasPin()) {
            throw new InvalidPinOperationException("PIN not set for user");
        }
        enforcePinChangeCooldown(user);
        ensurePhoneBelongsToUser(userId, phone);
    }

    /**
     * Step 1, second half: sends the PIN change code and records the challenge. It authorizes nothing,
     * so its only caller is {@link PinChangeService}, after {@link #preparePinChange(String, String)}
     * and an accepted factor.
     */
    String issuePinChangeChallenge(String userId, String phone, String requesterIp) {
        // The challenge id is minted before the send because the code is keyed under it, out of reach of
        // the unauthenticated public send.
        String challengeId = UUID.randomUUID().toString();
        otpService.sendScopedOtp(OtpScope.PIN_CHANGE, challengeId, phone, requesterIp, null);

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
            // Mismatched owner: destroy the challenge and the code that belonged to it.
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

    /**
     * Enforces the per-account phone-change cooldown. No-op for accounts that have
     * never changed their number. Throws {@link PhoneChangeCooldownException} (425 +
     * Retry-After) while the cooldown window from the last change is still open.
     */
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

    /**
     * Seconds still to run on the hold that keeps a freshly set PIN from being spent as the
     * phone-change step-up factor; {@code 0} when nothing is held.
     *
     * <p>A login session can create, change or recover a PIN, so without the hold a SIM-swap attacker
     * who reaches a session could set a PIN and re-point the number at once. The window is
     * {@code identity.security.pin-reset-cooldown}. {@code pin_set_at} is stamped on every path that
     * gives the account a new PIN (initial set, update, OTP-protected change, account recovery).
     */
    @Transactional(readOnly = true)
    public long changePhonePinHoldRemainingSeconds(String userId) {
        return repository.findByUserId(userId)
                .map(this::pinHoldRemainingSeconds)
                .orElse(0L);
    }

    /**
     * Refuses a phone change whose step-up PIN is still inside the fresh-2FA hold. In addition to the
     * per-account phone-change cooldown, which still runs.
     */
    @Transactional(readOnly = true)
    public void enforcePhoneChangePinHold(String userId) {
        long remaining = changePhonePinHoldRemainingSeconds(userId);
        if (remaining > 0) {
            throw new TwoFactorCooldownException(
                    "Two-step verification was set up too recently to change the phone number", remaining);
        }
    }

    /**
     * Refuses a phone change whose accepted step-up factor came into existence inside the fresh-2FA
     * hold, on the same window and with the same error as the PIN above. Takes the instant, not the
     * account: this service must not decide anything from what else an account holds.
     *
     * @param factorCreatedAt when the factor that was accepted came into being
     */
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

    /**
     * How long a factor stamped at {@code factorCreatedAt} is still too new to move the
     * phone number. One implementation, so two factors held for the same reason cannot drift
     * into being held for different lengths of time.
     */
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

    /**
     * Stamps the time of a successful phone-number change. Called inside the swap transaction so the
     * cooldown clock starts atomically with the mapping switch. Creates the row when the account has
     * none, and locks it like every other writer of this row.
     */
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
        // Producing the PIN ends any pending account recovery: somebody who can produce the PIN is not
        // locked out, and a recovery left running would hand the account to whoever started it.
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

    // Row-locked primitives for AccountRecoveryService and the login enrollment step. They hold no
    // policy of their own: the caller decides inside its own transaction.

    /** Reads the account row without locking it, for status answers that write nothing. */
    Optional<IdentityUser> findUser(String userId) {
        return repository.findByUserId(userId);
    }

    /** Locks the account row for the rest of the caller's transaction, if the row exists. */
    Optional<IdentityUser> lockUser(String userId) {
        return repository.findByUserIdForUpdate(userId);
    }

    /**
     * Locks the account row, creating it first when the account has never had one. The insert is
     * flushed at once, so two transactions creating the same row meet on the {@code user_id} unique
     * index and the second fails with a {@code DataIntegrityViolationException}.
     */
    IdentityUser lockOrCreateUser(String userId) {
        return repository.findByUserIdForUpdate(userId)
                .orElseGet(() -> repository.saveAndFlush(IdentityUser.builder().userId(userId).build()));
    }

    /** Locks the row of an account that must already have one. */
    private IdentityUser requireLockedUser(String userId) {
        return repository.findByUserIdForUpdate(userId)
                .orElseThrow(() -> new UnknownUserException("Unknown user: " + userId));
    }

    /** Opens a recovery episode on a locked row. The stamp is {@code pin_reset_requested_at}. */
    void openRecoveryEpisode(IdentityUser user, Instant requestedAt) {
        user.setPinResetRequestedAt(requestedAt);
    }

    /** Ends a recovery episode on a locked row without touching anything else. */
    void endRecoveryEpisode(IdentityUser user) {
        user.setPinResetRequestedAt(null);
    }

    /** Records account activity that counts against the recovery dormancy period. */
    void recordAccountActivity(IdentityUser user, Instant at) {
        user.setLastLoginAt(at);
    }

    /**
     * Checks a new PIN against the format and weak-PIN policy without applying it or counting
     * anything against the account.
     */
    void validateNewPin(String newPin) {
        validatePinFormat(newPin);
    }

    /**
     * Gives a locked row the PIN a completed recovery chose: validated like every other new PIN,
     * stamped {@code pin_set_at = now} so the fresh-factor hold applies to it, with the episode ended
     * and any failure count or lock cleared.
     */
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
