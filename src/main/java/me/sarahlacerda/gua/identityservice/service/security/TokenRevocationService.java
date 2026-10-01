package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Instant;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

/** A per-user cutoff in Redis: an access token whose iat predates it is revoked. */
@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private static final String KEY_PREFIX = "oidc:revoke-before:";

    private final StringRedisTemplate redisTemplate;

    public void revokeAllTokens(String userId) {
        long cutoff = Instant.now().getEpochSecond();
        redisTemplate.opsForValue().set(KEY_PREFIX + userId, Long.toString(cutoff));
    }

    /** A missing issuedAt is treated as revoked. */
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
