package me.sarahlacerda.gua.identityservice.service.security;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException;

@Service
@RequiredArgsConstructor
public class ReauthTokenService {

    private static final String KEY_PREFIX = "reauth:token:";
    private static final Duration TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    public String issue(String userId, ReauthOperation operation) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redisTemplate.opsForValue().set(KEY_PREFIX + token, userId + "|" + operation.name(), TTL);
        return token;
    }

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
