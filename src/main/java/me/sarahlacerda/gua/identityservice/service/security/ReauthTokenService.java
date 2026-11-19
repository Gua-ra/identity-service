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
 * Mints and consumes short-lived single-use reauth tokens that bind a fresh phone-OTP verification
 * to one sensitive account operation. Modeled after the Matrix {@code m.login.msisdn} UIA stage.
 * The token never grants long-term access: its TTL is short and it is deleted on first use.
 */
@Service
@RequiredArgsConstructor
public class ReauthTokenService {

    private static final String KEY_PREFIX = "reauth:token:";
    private static final Duration TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Mints a reauth token bound to {@code userId} and the {@code operation} it may be spent on. The
     * Redis value is {@code userId|OPERATION}, so consumption can reject a token presented for a
     * different operation.
     */
    public String issue(String userId, ReauthOperation operation) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redisTemplate.opsForValue().set(KEY_PREFIX + token, userId + "|" + operation.name(), TTL);
        return token;
    }

    /**
     * Atomically validates the token, deletes it, and returns the bound user id.
     * Throws if the token is unknown, expired, does not match
     * {@code expectedUserId}, or was issued for a different
     * {@code expectedOperation}.
     */
    public String consume(String token, String expectedUserId, ReauthOperation expectedOperation) {
        if (!StringUtils.hasText(token)) {
            throw new InvalidReauthTokenException("Reauth token invalid or expired");
        }
        String key = KEY_PREFIX + token;
        String stored = redisTemplate.opsForValue().getAndDelete(key);
        if (!StringUtils.hasText(stored)) {
            throw new InvalidReauthTokenException("Reauth token invalid or expired");
        }
        // Value is userId|OPERATION. A legacy value with no operation is rejected.
        int sep = stored.lastIndexOf('|');
        if (sep < 0) {
            throw new InvalidReauthTokenException("Reauth token is not scoped to this operation");
        }
        String boundUserId = stored.substring(0, sep);
        String boundOperation = stored.substring(sep + 1);
        if (!boundUserId.equals(expectedUserId)) {
            throw new InvalidReauthTokenException("Reauth token does not match caller");
        }
        if (!boundOperation.equals(expectedOperation.name())) {
            throw new InvalidReauthTokenException("Reauth token is not scoped to this operation");
        }
        return boundUserId;
    }
}
