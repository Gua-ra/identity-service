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
 * The OTP reauthentication that gates the sensitive account operations (phone change, deactivation,
 * identity reset), in the spirit of the Matrix {@code m.login.msisdn} UIA stage.
 *
 * <p>The signed-in user types their current number; it is normalized, digested with the directory's
 * peppered HMAC and compared with the digests of that account's own {@code directory_entries} rows.
 * Only a match sends the code. Consequences:
 * <ul>
 * <li>No raw number is stored and nothing is written between the two calls.</li>
 * <li>The refusal is identical whether the number is unknown, belongs to somebody else or is not
 * this account's, so it cannot be used to ask who owns a number.</li>
 * <li>It does not depend on the homeserver's threepid bindings.</li>
 * </ul>
 *
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
     * Exchanges the code for a reauth token scoped to {@code operation}. The number is checked again
     * here, since nothing is persisted between the two calls.
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
     * Normalizes the submitted number and returns it in E.164 when it is one of this account's own,
     * refusing with {@link ReauthPhoneMismatchException} when it is not.
     *
     * <p>An attempt is reserved from the hour's budget before the comparison and released on a match,
     * so only mismatches spend the budget. A number that does not parse is refused earlier with
     * {@code 400 invalid_phone_number}, which depends on the submitted string alone and costs no attempt.
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
     * Whether {@code phone} is the number bound to {@code userId}: the digest of the submitted number
     * against the digests of the account's own directory rows. On a miss it falls back to the
     * homeserver's phone binding, so pepper drift does not lock an account out. The fallback is best
     * effort: a failed lookup is a miss, never an accepted number.
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
     * Takes one attempt out of the account's hour budget, refusing once the budget is spent. INCR
     * first and compare the result, so a parallel burst cannot pass the gate. A counter that cannot be
     * updated refuses the attempt. The message is written here because the generic limiter's message
     * names its Redis key, which carries the user id.
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
     * Opens the hour window on the counter. Re-armed on every attempt inside the budget, so a key that
     * lost its expiry cannot block the account for good. Not re-armed once the budget is spent, so a
     * flood of refused attempts cannot extend the window.
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
            // Leave the attempt spent: the caller has just proved the number.
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
