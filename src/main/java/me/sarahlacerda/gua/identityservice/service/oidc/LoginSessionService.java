package me.sarahlacerda.gua.identityservice.service.oidc;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;

@Service
@RequiredArgsConstructor
public class LoginSessionService {

    private static final String KEY_PREFIX = "oidc:login:";
    private static final String ENROLL_TOKEN_PREFIX = "oidc:login:enroll:";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final LoginFlowProperties properties;

    public String create(LoginSession session) {
        String id = newToken();
        save(id, session);
        return id;
    }

    public Optional<LoginSession> find(String id) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        String payload = redisTemplate.opsForValue().get(keyFor(id));
        if (payload == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(objectMapper.readValue(payload, LoginSession.class));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to deserialize login session", ex);
        }
    }

    /** Resets the TTL so an active login does not expire mid-flow. */
    public void save(String id, LoginSession session) {
        try {
            redisTemplate.opsForValue().set(
                    keyFor(id),
                    objectMapper.writeValueAsString(session),
                    properties.getSessionTtl());
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize login session", ex);
        }
    }

    public void delete(String id) {
        if (id != null && !id.isBlank()) {
            redisTemplate.delete(keyFor(id));
        }
    }

    // The API POST's cookie is not present in the web view, so the web view redeems this one-time token for a
    // session cookie.
    public String createEnrollToken(String sessionId, Duration ttl) {
        String token = newToken();
        redisTemplate.opsForValue().set(enrollTokenKey(token), sessionId, ttl);
        return token;
    }

    public Optional<String> consumeEnrollToken(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(redisTemplate.opsForValue().getAndDelete(enrollTokenKey(token)));
    }

    public String newToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String keyFor(String id) {
        return KEY_PREFIX + id;
    }

    private String enrollTokenKey(String token) {
        return ENROLL_TOKEN_PREFIX + token;
    }
}
