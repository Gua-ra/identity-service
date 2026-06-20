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

/**
 * Redis-backed store for {@link LoginSession}s. Sessions are keyed by an
 * opaque,
 * high-entropy identifier delivered to the browser as an HttpOnly cookie, and
 * expire after {@link LoginFlowProperties#getSessionTtl()}.
 */
@Service
@RequiredArgsConstructor
public class LoginSessionService {

    private static final String KEY_PREFIX = "oidc:login:";
    private static final String ENROLL_TOKEN_PREFIX = "oidc:login:enroll:";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final LoginFlowProperties properties;

    /** Persists a new session and returns its opaque identifier. */
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

    /**
     * Writes the session, (re)setting its TTL so an active login does not expire
     * mid-flow.
     */
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

    /**
     * Issues a one-time token mapping to a login session id, used by the in-app
     * passkey enrollment handoff. The cookie set on the (separate-context) API POST
     * is not present in the web view, so the web view opens this token and the GET
     * handler turns it back into a first-party session cookie. Stored with a short
     * TTL and consumed on first read.
     */
    public String createEnrollToken(String sessionId, Duration ttl) {
        String token = newToken();
        redisTemplate.opsForValue().set(enrollTokenKey(token), sessionId, ttl);
        return token;
    }

    /** Atomically reads and removes a one-time enroll token, returning its session id. */
    public Optional<String> consumeEnrollToken(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(redisTemplate.opsForValue().getAndDelete(enrollTokenKey(token)));
    }

    /** Generates an opaque token suitable for a session id or a CSRF token. */
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
