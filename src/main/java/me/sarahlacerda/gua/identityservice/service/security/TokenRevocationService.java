package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Instant;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

/**
 * Per-user revoke-before cutoff that invalidates every outstanding stateless RS256 access token for
 * a user before its natural expiry. Used when an account is deactivated or its credentials are reset.
 *
 * <p>The cutoff is a Unix-second timestamp in Redis. An access token is revoked when its {@code iat}
 * predates the cutoff, which keeps verification stateless apart from one Redis read.
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
     * Returns {@code true} when a token with the given {@code issuedAt} should be rejected for
     * {@code userId}. A missing {@code issuedAt} is treated as revoked.
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
