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
     * Sets the first PIN on a row the caller has already locked. Package-private for the
     * enrollment step of the login flow, which has to weigh what else the account holds under the
     * same lock before it decides this PIN may be set at all.
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
     * Step 1, second half: sends the PIN change code and records the challenge. Package-private
     * and unguarded on purpose: it authorizes nothing, so its only caller is
     * {@link PinChangeService}, after {@link #preparePinChange(String, String)} and an accepted
     * factor.
     */
    String issuePinChangeChallenge(String userId, String phone, String requesterIp) {
        // The challenge id is minted before the send because it is what the code is keyed
        // under. Scoped to this challenge, the code cannot be planted by, or satisfied by,
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
     * Seconds still to run on the hold that keeps a freshly minted PIN from being spent as
     * the phone-change step-up factor; {@code 0} when nothing is held.
     *
     * <p>
     * A login session can create, change or recover a PIN, and that PIN is then accepted as
     * the step-up factor on a phone change. The permissive login side is therefore itself a
     * route to re-pointing the number, and a SIM-swap attacker who reaches a session only
     * has to set a PIN of their own. Holding the new PIN for a window closes that without
     * taking any factor away from anyone: nothing is refused permanently, the account keeps
     * every way in it had, and the hold simply expires.
     *
     * <p>
     * The window is {@code identity.security.pin-reset-cooldown}, which also applies to a PIN
     * obtained through account recovery (it is stamped the same way), rather than a second
     * seven-day constant sitting next to it. Both express the same thing: a knowledge factor that has
     * only just come into existence is not yet trusted for a takeover-shaped action. An
     * operator who retunes one is retuning both, deliberately.
     *
     * <p>
     * {@code pin_set_at} is stamped on every path that gives the account a new PIN (initial
     * set, update, OTP-protected change, account recovery), so it is exactly "when the current PIN came
     * into being". An account with no PIN, or one whose stamp predates the window, is not
     * held.
     */
    @Transactional(readOnly = true)
    public long changePhonePinHoldRemainingSeconds(String userId) {
        return repository.findByUserId(userId)
                .map(this::pinHoldRemainingSeconds)
                .orElse(0L);
    }

    /**
     * Refuses a phone change whose step-up PIN is still inside the fresh-2FA hold. An
     * ADDITIONAL refusal: it never stands in for the per-account phone-change cooldown or
     * for the account recovery gates, which are unchanged and still run.
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
     * Refuses a phone change whose accepted step-up factor came into existence inside the
     * fresh-2FA hold, on the same window and with the same error as the PIN above.
     *
     * <p>
     * Deliberately knows nothing about which factor it is weighing, and takes the instant
     * rather than an account: which factors exist, and why a newly minted one is not yet
     * trusted for a takeover-shaped action, is the caller's business. This service owns PIN
     * recovery, and the one thing it must never learn to do is decide anything from what
     * else an account holds.
     *
     * <p>
     * Nothing is taken away by it. An established factor settles the step-up at once, every
     * other way through is untouched, and the refusal expires on its own.
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
            // No stamp. Both stamps are NOT NULL columns written when the factor comes into
            // being, so the only row that could lack one is older than the column itself,
            // which is the opposite of a factor minted a moment ago.
            return 0L;
        }
        Duration hold = properties.getSecurity().getPinResetCooldown();
        Duration since = Duration.between(factorCreatedAt, Instant.now());
        if (since.isNegative()) {
            // Clock skew put the stamp in the future. Hold for the whole window rather than
            // for longer than the window.
            return hold.toSeconds();
        }
        if (since.compareTo(hold) >= 0) {
            return 0L;
        }
        // Never round a live hold down to zero, which would read as "no hold".
        return Math.max(hold.minus(since).toSeconds(), 1L);
    }

    /**
     * Stamps the time of a successful phone-number change. Called inside the swap
     * transaction so the cooldown clock starts atomically with the mapping switch.
     * Uses {@link #ensureUser(String)} because a token-only account may not yet have
     * an identity_users row.
     */
    @Transactional
    public void stampPhoneChange(String userId) {
        IdentityUser user = ensureUser(userId);
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
        // Producing the PIN ends any account recovery pending on this account. Somebody who can
        // produce the PIN is not the person locked out of it, and a recovery left running would
        // hand the account to whoever started it once the wait is over. This is not a challenge
        // restarting the clock, which stays forbidden; it is the episode being over.
        user.setPinResetRequestedAt(null);
        auditLogger.pinValidationSucceeded(userId);
    }

    @Transactional
    public void recordSuccessfulLogin(String userId) {
        // Locked, because this write races the recovery writers: an unlocked read here followed
        // by a full-row update could put back a PIN hash or a recovery stamp that a concurrent
        // recovery completion or cancel had just committed.
        IdentityUser user = lockOrCreateUser(userId);
        user.setLastLoginAt(Instant.now());
        resetFailureTracking(user);
        // A finished sign-in ends any recovery episode pending on the account, for the reason
        // spelled out on validatePinOrThrow. Only a completed login reaches here, which means the
        // account holder produced whatever that account's login demands, so they are not the
        // person locked out of it. A recovery completion has already ended its own episode by
        // the time its sign-in is recorded, so this never stands in its way.
        user.setPinResetRequestedAt(null);
    }

    // ---------------------------------------------------------------------------------------
    // Row-locked primitives for AccountRecoveryService and the login enrollment step. They hold
    // no policy of their own: what the account holds beyond its PIN, and whether an episode may
    // open, finish or end, is decided by the caller inside its own transaction.
    // ---------------------------------------------------------------------------------------

    /** Reads the account row without locking it, for status answers that write nothing. */
    Optional<IdentityUser> findUser(String userId) {
        return repository.findByUserId(userId);
    }

    /** Locks the account row for the rest of the caller's transaction, if the row exists. */
    Optional<IdentityUser> lockUser(String userId) {
        return repository.findByUserIdForUpdate(userId);
    }

    /**
     * Locks the account row, creating it first when the account has never had one. An account
     * that signed in only through paths that never wrote security state has no row yet.
     */
    IdentityUser lockOrCreateUser(String userId) {
        return repository.findByUserIdForUpdate(userId)
                .orElseGet(() -> repository.save(IdentityUser.builder().userId(userId).build()));
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
     * stamped {@code pin_set_at = now} so the fresh-factor hold on a phone change applies to it,
     * with the episode ended and any failure count or lock cleared.
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
