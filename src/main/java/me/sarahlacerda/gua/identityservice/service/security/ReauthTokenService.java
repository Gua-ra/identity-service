package me.sarahlacerda.gua.identityservice.service.security;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException;

/**
 * Mints and consumes short-lived single-use "reauth" tokens that bind a fresh
 * phone-OTP
 * verification to a sensitive account operation (deactivate, reset identity).
 *
 * <p>
 * Modeled after the Matrix {@code m.login.msisdn} UIA stage: the user re-proves
 * possession of
 * their registered phone number and we issue an opaque token the client
 * immediately spends on a
 * single privileged operation. The token never grants long-term access — its
 * TTL is short and we
 * delete it on first use.
 * </p>
 */
@Service
@RequiredArgsConstructor
public class ReauthTokenService {

    private static final String KEY_PREFIX = "reauth:token:";
    private static final Duration TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    public String issue(String userId) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redisTemplate.opsForValue().set(KEY_PREFIX + token, userId, TTL);
        return token;
    }

    /**
     * Atomically validates the token, deletes it, and returns the bound user id.
     * Throws if the
     * token is unknown, expired, or does not match {@code expectedUserId}.
     */
    public String consume(String token, String expectedUserId) {
        if (!StringUtils.hasText(token)) {
            throw new InvalidReauthTokenException("Reauth token invalid or expired");
        }
        String key = KEY_PREFIX + token;
        String boundUserId = redisTemplate.opsForValue().getAndDelete(key);
        if (!StringUtils.hasText(boundUserId)) {
            throw new InvalidReauthTokenException("Reauth token invalid or expired");
        }
        if (!boundUserId.equals(expectedUserId)) {
            throw new InvalidReauthTokenException("Reauth token does not match caller");
        }
        return boundUserId;
    }

    /**
     * Validates the token WITHOUT consuming it (a "peek"), for multi-step flows that need to gate an
     * intermediate side-effect — e.g. sending the new-number OTP only after the PIN step-up — while
     * keeping the token alive to be {@link #consume(String, String) consumed} on the final operation.
     * Throws if the token is unknown, expired, or does not match {@code expectedUserId}.
     */
    public void validate(String token, String expectedUserId) {
        if (!StringUtils.hasText(token)) {
            throw new InvalidReauthTokenException("Reauth token invalid or expired");
        }
        String boundUserId = redisTemplate.opsForValue().get(KEY_PREFIX + token);
        if (!StringUtils.hasText(boundUserId)) {
            throw new InvalidReauthTokenException("Reauth token invalid or expired");
        }
        if (!boundUserId.equals(expectedUserId)) {
            throw new InvalidReauthTokenException("Reauth token does not match caller");
        }
    }
}
