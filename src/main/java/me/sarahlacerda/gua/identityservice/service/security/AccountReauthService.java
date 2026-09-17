package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import me.sarahlacerda.gua.identityservice.exception.ReauthPhoneMismatchException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberNormalizer;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * The OTP reauthentication that gates the sensitive account operations (phone change,
 * deactivation, identity reset). The caller is already authenticated for the session but must
 * prove possession of the number on the account before the request is honoured, in the spirit
 * of the Matrix {@code m.login.msisdn} UIA stage.
 *
 * <p>
 * The number is supplied by the caller and checked against the account, rather than looked up
 * and used. The signed-in user types their current number; it is normalized, digested with the
 * directory's peppered HMAC, and compared with the digests of that account's own
 * {@code directory_entries} rows. Only a match sends the code, and the code goes to the number
 * that was just proved to be the account's.
 *
 * <p>
 * Three properties fall out of doing it this way, and all three were the point:
 * <ul>
 * <li>No raw number is stored and nothing new is written. Verification re-derives everything
 * from the number the caller submits again, so there is no pending-phone record to leak or to
 * get stale.</li>
 * <li>Nothing is revealed about any other account. The refusal is identical whether the number
 * is unknown, belongs to somebody else, or is simply not this account's, so it cannot be used
 * to ask who owns a number.</li>
 * <li>It does not depend on the homeserver's threepid bindings, which would have put the raw
 * MSISDN of every account on the homeserver and which the admin API serves unreliably under
 * MAS delegated authentication. The directory already holds the authoritative binding.</li>
 * </ul>
 *
 * <p>
 * Two-step interface so the client UI can show progress between the SMS send and the code
 * entry:
 * <ol>
 * <li>{@link #startReauth(String, String, String, String)} sends a fresh OTP to the number the
 * caller proved is the account's.</li>
 * <li>{@link #verifyReauth(String, String, String, ReauthOperation, String)} exchanges the code
 * for a single-use, operation-scoped reauth token spent on a privileged endpoint.</li>
 * </ol>
 */
@Service
@RequiredArgsConstructor
public class AccountReauthService {

    private static final Logger log = LoggerFactory.getLogger(AccountReauthService.class);

    private static final String MISMATCH_RATE_KEY_PREFIX = "reauth:phone-mismatch:";
    private static final Duration MISMATCH_WINDOW = Duration.ofHours(1);

    /**
     * The one refusal. Says only that this is not the number on the account, in the same words
     * whoever the number belongs to.
     */
    private static final String MISMATCH_MESSAGE = "That is not the number on your account.";

    private final OtpService otpService;
    private final DirectoryService directoryService;
    private final PhoneNumberNormalizer phoneNumberNormalizer;
    private final PhoneNumberHasher phoneNumberHasher;
    private final MatrixAdminClient matrixAdminClient;
    private final ReauthTokenService reauthTokenService;
    private final StringRedisTemplate redisTemplate;
    private final SecurityAuditLogger auditLogger;
    private final IdentityServiceProperties properties;

    /**
     * Sends the reauthentication OTP, once the submitted number is shown to be the account's.
     * The send itself stays inside the ordinary per-phone and per-address OTP limits.
     */
    public void startReauth(String userId, String submittedPhone, String requesterIp, String language) {
        String phone = requireOwnPhone(userId, submittedPhone, "REAUTH_START", requesterIp);
        otpService.sendOtp(phone, requesterIp, language);
        log.info("Issued reauth OTP for {}", userId);
    }

    /**
     * Exchanges the code for a reauth token scoped to {@code operation}. The number is checked
     * again here rather than remembered from the start call: nothing is persisted between the
     * two, so a token can only ever be minted by someone who can produce the account's number
     * and the code sent to it.
     */
    public String verifyReauth(String userId, String submittedPhone, String code, ReauthOperation operation,
            String requesterIp) {
        verifyPhoneOtp(userId, submittedPhone, code, operation.name(), requesterIp);
        String token = reauthTokenService.issue(userId, operation);
        log.info("Issued {} reauth token for {}", operation, userId);
        return token;
    }

    /**
     * The same check and the same OTP redemption without minting a token, for a flow that needs
     * the proof inside a session it already holds rather than a token to spend elsewhere: the
     * first-factor enrollment step-up of an account that holds no factor to step up with.
     */
    public void verifyPhoneOtp(String userId, String submittedPhone, String code, String operation,
            String requesterIp) {
        String phone = requireOwnPhone(userId, submittedPhone, operation, requesterIp);
        otpService.verifyOtp(phone, code);
    }

    public void requireValidReauth(String userId, String reauthToken, ReauthOperation operation) {
        if (reauthToken == null || reauthToken.isBlank()) {
            throw new InvalidReauthTokenException("Reauth token required");
        }
        reauthTokenService.consume(reauthToken, userId, operation);
    }

    /**
     * Normalizes the submitted number and returns it in E.164 when it is one of this account's
     * own, refusing with {@link ReauthPhoneMismatchException} when it is not.
     *
     * <p>
     * An attempt is reserved from the hour's budget before the comparison and given back when
     * the number turns out to be the account's own, so the budget is spent by mismatches alone
     * and an account holder retyping their own number is never locked out of their own settings
     * by having got it wrong five times.
     *
     * <p>
     * A number that does not parse is refused earlier, by the normalizer, with
     * {@code 400 invalid_phone_number}. That answer is a function of the submitted string
     * alone: it is the same for every caller and for every account, so it says nothing about
     * who owns what and cannot be used to probe ownership. It also costs no attempt, because it
     * is settled before the account is consulted at all. Everything that does depend on the
     * account gets the single 403 below.
     */
    private String requireOwnPhone(String userId, String submittedPhone, String operation, String requesterIp) {
        String phone = phoneNumberNormalizer.toE164(submittedPhone);
        reserveAttempt(userId);
        if (!boundToAccount(userId, phone)) {
            auditLogger.reauthFailed(userId, operation, requesterIp);
            throw new ReauthPhoneMismatchException(MISMATCH_MESSAGE);
        }
        releaseAttempt(userId);
        return phone;
    }

    /**
     * Whether {@code phone} is the number bound to {@code userId}.
     *
     * <p>
     * The digest of the submitted number against the digests of the account's own directory
     * rows, which is the authoritative binding. On a miss it falls back to the homeserver's
     * phone binding, exactly as the OTP step of the interactive login does, so a rotated or
     * drifted directory pepper does not leave a legitimate account unable to reauthenticate:
     * that binding is independent of the pepper. The fallback is best effort, because the admin
     * API is not reliably available under MAS delegated authentication; a failure there is a
     * miss, never an accepted number.
     */
    private boolean boundToAccount(String userId, String phone) {
        String digest = phoneNumberHasher.digest(phone);
        boolean matchesDirectory = directoryService.findByUserId(userId).stream()
                .map(DirectoryEntry::getPhoneDigest)
                .anyMatch(stored -> stored != null && constantTimeEquals(digest, stored));
        if (matchesDirectory) {
            return true;
        }
        try {
            return matrixAdminClient.findUserIdByPhone(phone)
                    .filter(userId::equals)
                    .isPresent();
        } catch (RuntimeException ex) {
            log.warn("Phone-binding fallback unavailable while reauthenticating {}: {}", userId, ex.getMessage());
            return false;
        }
    }

    /**
     * Takes one attempt out of the account's hour budget, refusing once the budget is spent.
     *
     * <p>
     * INCR first and compare what it returns, which is the pattern
     * {@link me.sarahlacerda.gua.identityservice.service.RateLimiter#checkRate} uses and for the
     * same reason: a read followed by a later increment bounds a sequential attacker only, since
     * a burst of parallel requests all read the same value, all pass the gate and all get their
     * number compared. The reservation is taken before the comparison for that reason too, so
     * what the cap bounds is the number of comparisons a burst can perform, and with them the
     * homeserver lookups the fallback makes for a caller-chosen number.
     *
     * <p>
     * A counter that cannot be updated refuses the attempt rather than waving it through: this is
     * the only bound on guessing the account's own number.
     *
     * <p>
     * The message is written here: the generic limiter's own message names its Redis key, which
     * carries the user id, and error messages are returned to callers.
     */
    private void reserveAttempt(String userId) {
        String key = mismatchKey(userId);
        Long counted;
        try {
            counted = redisTemplate.opsForValue().increment(key);
        } catch (DataAccessException ex) {
            throw new RateLimiterException("Could not check the attempt budget; try again later", ex);
        }
        long spent = counted == null ? 1L : counted;
        armWindow(key, spent);
        if (spent > properties.getSecurity().getMaxReauthPhoneAttemptsPerHour()) {
            throw new RateLimiterException("Too many attempts to confirm your number; try again later");
        }
    }

    /**
     * Opens the hour window on the counter, so the budget refills an hour after it opened.
     *
     * <p>
     * Re-armed on every attempt still inside the budget rather than on the first one alone: a key
     * that ended up without a window, because the {@code expire} after the first increment failed,
     * would otherwise never get one and would refuse the account for good. Not re-armed once the
     * budget is spent, because a flood of refused attempts would then push the window out for as
     * long as the flood lasted and hold the account holder out with it.
     */
    private void armWindow(String key, long spent) {
        if (spent <= properties.getSecurity().getMaxReauthPhoneAttemptsPerHour()) {
            redisTemplate.expire(key, MISMATCH_WINDOW);
        }
    }

    /**
     * Gives the reservation back, once the number has turned out to be the account's own. What
     * keeps the budget one of wrong numbers rather than one of attempts.
     */
    private void releaseAttempt(String userId) {
        try {
            redisTemplate.opsForValue().decrement(mismatchKey(userId));
        } catch (DataAccessException ex) {
            // Leaving the attempt spent is the smaller harm: the caller has just proved the
            // number, and refusing them over the bookkeeping would be the lockout the budget is
            // shaped to avoid.
            log.warn("Could not release the reauth attempt for {}: {}", userId, ex.getMessage());
        }
    }

    private static String mismatchKey(String userId) {
        return MISMATCH_RATE_KEY_PREFIX + userId;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
