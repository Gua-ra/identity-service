package me.sarahlacerda.gua.identityservice.service.oidc;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;

/**
 * Mints and redeems OAuth 2.0 authorization codes. This service never
 * authenticates anyone: the caller must already hold a fully resolved
 * {@link OidcAuthorization}, which only the interactive login flow produces
 * after the phone, OTP and PIN/profile steps. The former non-interactive path
 * that accepted an OTP directly is removed (ADM-001 L1a).
 */
@Service
@RequiredArgsConstructor
public class OidcAuthorizationService {

    private static final String CODE_KEY_PREFIX = "oidc:code:";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final OidcProperties properties;

    /**
     * Generates a one-time authorization code for an already-authenticated
     * authorization and stores it in Redis until it is exchanged at the token
     * endpoint. Used by the interactive browser login flow, which resolves the
     * user across several steps (phone, OTP, PIN/profile) before calling this.
     */
    public OidcAuthorizationCode issueCode(OidcAuthorization authorization, String redirectUri, String codeChallenge) {
        String code = generateCode();
        persist(code, authorization, redirectUri, codeChallenge);
        return new OidcAuthorizationCode(code, authorization, redirectUri,
                Optional.ofNullable(codeChallenge));
    }

    public Optional<OidcAuthorizationCode> consumeAuthorizationCode(String code) {
        String key = keyFor(code);
        String payload = redisTemplate.opsForValue().get(key);
        if (payload == null) {
            return Optional.empty();
        }
        redisTemplate.delete(key);
        try {
            AuthorizationCodePayload stored = objectMapper.readValue(payload, AuthorizationCodePayload.class);
            OidcAuthorization authorization = new OidcAuthorization(
                    stored.userId(),
                    stored.phoneNumber(),
                    stored.displayName(),
                    stored.preferredUsername(),
                    Set.copyOf(stored.scope()),
                    stored.clientId(),
                    stored.nonce(),
                    // Absent from a code stored before the field existed, which is never a recovery.
                    Boolean.TRUE.equals(stored.endOtherSessions()));
            return Optional.of(new OidcAuthorizationCode(code, authorization, stored.redirectUri(),
                    Optional.ofNullable(stored.codeChallenge())));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to deserialize authorization code", ex);
        }
    }

    private void persist(String code, OidcAuthorization authorization, String redirectUri, String codeChallenge) {
        AuthorizationCodePayload payload = new AuthorizationCodePayload(
                authorization.userId(),
                authorization.phoneNumber(),
                authorization.displayName(),
                authorization.preferredUsername(),
                authorization.scope(),
                authorization.clientId(),
                authorization.nonce(),
                redirectUri,
                codeChallenge,
                authorization.endOtherSessions());
        try {
            redisTemplate.opsForValue().set(
                    keyFor(code),
                    objectMapper.writeValueAsString(payload),
                    properties.getAuthorizationCodeTtl());
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize authorization code", ex);
        }
    }

    private String keyFor(String code) {
        return CODE_KEY_PREFIX + code;
    }

    private String generateCode() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private record AuthorizationCodePayload(
            String userId,
            String phoneNumber,
            String displayName,
            String preferredUsername,
            Set<String> scope,
            String clientId,
            String nonce,
            String redirectUri,
            String codeChallenge,
            Boolean endOtherSessions) {
    }
}
