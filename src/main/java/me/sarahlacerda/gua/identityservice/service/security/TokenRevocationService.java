package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;
import java.time.Instant;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.config.OidcProperties;

/**
 * Per-user "revoke-before" cutoff that lets the service invalidate every
 * outstanding stateless RS256 access token for a user before its natural
 * expiry. Used when an account is deactivated, deleted or its credentials are reset.
 *
 * <p>
 * The cutoff is a Unix-second timestamp stored in Redis. An access token is
 * considered revoked when its {@code iat} (issued-at) predates the cutoff. This
 * keeps the common verification path stateless (a single Redis read only when a
 * cutoff exists) while still giving us a global logout primitive.
 * </p>
 *
 * <p>
 * The cutoff expires once every token it can refuse has expired on its own: it outlives the access
 * token lifetime, with a floor of {@link #MINIMUM_TTL}, so no key named after an account stays in
 * Redis for good.
 * </p>
 */
@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private static final String KEY_PREFIX = "oidc:revoke-before:";

    static final Duration MINIMUM_TTL = Duration.ofHours(1);

    /** Covers clock skew between the instance that issued a token and the one that checks it. */
    private static final Duration SKEW_MARGIN = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;
    private final OidcProperties oidcProperties;

    /** Invalidate every access token issued to {@code userId} up to now. */
    public void revokeAllTokens(String userId) {
        long cutoff = Instant.now().getEpochSecond();
        redisTemplate.opsForValue().set(KEY_PREFIX + userId, Long.toString(cutoff), cutoffTtl());
    }

    /**
     * Invalidate every access token issued to a deleted account, including any issued in the current
     * second. Token issue times have whole-second precision, so {@link #revokeAllTokens} spares a token
     * minted in the same second as the cutoff; a deleted account is never issued another token, so
     * there is nothing to spare.
     */
    public void revokeAllTokensOfDeletedAccount(String userId) {
        long cutoff = Instant.now().getEpochSecond() + 1;
        redisTemplate.opsForValue().set(KEY_PREFIX + userId, Long.toString(cutoff), cutoffTtl());
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

    Duration cutoffTtl() {
        Duration tokenLifetime = oidcProperties.getAccessTokenTtl().plus(SKEW_MARGIN);
        return tokenLifetime.compareTo(MINIMUM_TTL) > 0 ? tokenLifetime : MINIMUM_TTL;
    }
}
