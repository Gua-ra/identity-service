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

// The submitted number is checked against the account's directory digests; nothing is stored between calls.
// The refusal is identical for every kind of mismatch, so the endpoint cannot reveal who owns a number.
@Service
@RequiredArgsConstructor
public class AccountReauthService {

    private static final Logger log = LoggerFactory.getLogger(AccountReauthService.class);

    private static final String MISMATCH_RATE_KEY_PREFIX = "reauth:phone-mismatch:";
    private static final Duration MISMATCH_WINDOW = Duration.ofHours(1);

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

    public void startReauth(String userId, String submittedPhone, String requesterIp, String language) {
        String phone = requireOwnPhone(userId, submittedPhone, "REAUTH_START", requesterIp);
        otpService.sendOtp(phone, requesterIp, language);
        log.info("Issued reauth OTP for {}", userId);
    }

    public String verifyReauth(String userId, String submittedPhone, String code, ReauthOperation operation,
            String requesterIp) {
        verifyPhoneOtp(userId, submittedPhone, code, operation.name(), requesterIp);
        String token = reauthTokenService.issue(userId, operation);
        log.info("Issued {} reauth token for {}", operation, userId);
        return token;
    }

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

    /** An attempt is reserved before the comparison and released on a match, so only mismatches spend the budget. */
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

    // On a digest miss it checks the homeserver's phone binding, so pepper drift does not lock an account out.
    // A failed lookup is a miss.
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

    // INCR first and compare the result, so a parallel burst cannot pass the gate.
    // A counter that cannot be updated refuses the attempt.
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

    // Re-armed on every attempt inside the budget, so a key that lost its expiry cannot block the account.
    // Not re-armed once the budget is spent.
    private void armWindow(String key, long spent) {
        if (spent <= properties.getSecurity().getMaxReauthPhoneAttemptsPerHour()) {
            redisTemplate.expire(key, MISMATCH_WINDOW);
        }
    }

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
