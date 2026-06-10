package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Instant;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

/**
 * Per-user "revoke-before" cutoff that lets the service invalidate every
 * outstanding stateless RS256 access token for a user before its natural
 * expiry. Used when an account is deactivated or its credentials are reset.
 *
 * <p>
 * The cutoff is a Unix-second timestamp stored in Redis. An access token is
 * considered revoked when its {@code iat} (issued-at) predates the cutoff. This
 * keeps the common verification path stateless (a single Redis read only when a
 * cutoff exists) while still giving us a global logout primitive.
 * </p>
 */
@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private static final String KEY_PREFIX = "oidc:revoke-before:";

    private final StringRedisTemplate redisTemplate;

    /** Invalidate every access token issued to {@code userId} up to now. */
    public void revokeAllTokens(String userId) {
        long cutoff = Instant.now().getEpochSecond();
        redisTemplate.opsForValue().set(KEY_PREFIX + userId, Long.toString(cutoff));
    }

    /**
     * Returns {@code true} when a token with the given {@code issuedAt} should be
     * rejected for {@code userId}. A missing {@code issuedAt} is treated as revoked
     * (we cannot prove the token was issued after the cutoff).
     */
    public boolean isRevoked(String userId, Instant issuedAt) {
        if (issuedAt == null) {
            return true;
        }
        String cutoff = redisTemplate.opsForValue().get(KEY_PREFIX + userId);
        if (cutoff == null) {
            return false;
        }
        return issuedAt.getEpochSecond() < Long.parseLong(cutoff);
    }
}
