package me.sarahlacerda.gua.identityservice.service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinChallengeException;

/**
 * Issues short-lived single-use tokens that bind a verified phone OTP to a user
 * who has a PIN configured. The client redeems the token together with the PIN
 * at {@code POST /signin/verify-pin} to complete sign-in.
 *
 * <p>
 * Splitting OTP verification from PIN verification means the OTP is consumed
 * exactly once and never lost if the user takes a moment to enter their PIN,
 * and
 * it ensures the PIN is never sent in the same request as the SMS code that
 * proves possession of the phone.
 * </p>
 */
@Service
public class PinChallengeService {

    private static final String KEY_PREFIX = "pin:challenge:";
    private static final String FIELD_SEPARATOR = "|";
    private static final Duration TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    public PinChallengeService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String issue(String userId, String phone) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redisTemplate.opsForValue().set(KEY_PREFIX + token, userId + FIELD_SEPARATOR + phone, TTL);
        return token;
    }

    public Challenge consume(String token) {
        Challenge challenge = peek(token);
        redisTemplate.delete(KEY_PREFIX + token);
        return challenge;
    }

    /**
     * Returns the challenge bound to {@code token} without deleting it. Callers
     * that may need to
     * retry (e.g. wrong-PIN attempts within the {@link UserSecurityService} lockout
     * policy) should
     * peek first, validate, and only {@link #consume(String)} on success so the
     * user doesn't lose
     * their verified OTP after a single typo.
     */
    public Challenge peek(String token) {
        if (!StringUtils.hasText(token)) {
            throw new InvalidPinChallengeException("PIN challenge invalid or expired");
        }
        String payload = redisTemplate.opsForValue().get(KEY_PREFIX + token);
        if (!StringUtils.hasText(payload)) {
            throw new InvalidPinChallengeException("PIN challenge invalid or expired");
        }
        int separatorIndex = payload.indexOf(FIELD_SEPARATOR);
        if (separatorIndex <= 0 || separatorIndex == payload.length() - 1) {
            throw new InvalidPinChallengeException("PIN challenge invalid or expired");
        }
        return new Challenge(payload.substring(0, separatorIndex), payload.substring(separatorIndex + 1));
    }

    public record Challenge(String userId, String phone) {
    }
}
