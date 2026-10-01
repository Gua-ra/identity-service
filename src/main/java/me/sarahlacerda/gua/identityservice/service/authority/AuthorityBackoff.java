// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/**
 * Doubling backoff per account and authorizing key, held in Redis. An unreadable counter refuses the
 * initiation.
 */
@Service
public class AuthorityBackoff {

    private static final String KEY_PREFIX = "authority:backoff:";

    /** Must outlive the largest backoff the policy can issue. */
    private static final Duration RETENTION = Duration.ofDays(30);

    private final StringRedisTemplate redisTemplate;
    private final AuthorityPolicy policy;

    public AuthorityBackoff(StringRedisTemplate redisTemplate, AuthorityPolicy policy) {
        this.redisTemplate = redisTemplate;
        this.policy = policy;
    }

    public Optional<Instant> until(String account, String authorizingKeyB64) {
        String value = redisTemplate.opsForValue().get(key(account, authorizingKeyB64));
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(Instant.ofEpochSecond(Long.parseLong(value.split(":", 2)[1])));
        } catch (RuntimeException ex) {
            return Optional.of(Instant.MAX);
        }
    }

    public Instant recordCancellation(String account, String authorizingKeyB64, Instant now) {
        String redisKey = key(account, authorizingKeyB64);
        String existing = redisTemplate.opsForValue().get(redisKey);
        int cancellations = 1;
        if (existing != null) {
            try {
                cancellations = Integer.parseInt(existing.split(":", 2)[0]) + 1;
            } catch (RuntimeException ex) {
                cancellations = 1;
            }
        }
        Instant until = now.plus(policy.backoffAfter(cancellations));
        redisTemplate.opsForValue().set(redisKey, cancellations + ":" + until.getEpochSecond(), RETENTION);
        return until;
    }

    private static String key(String account, String authorizingKeyB64) {
        return KEY_PREFIX + AuthorityChallengeService.sha256Hex(account + "|" + authorizingKeyB64);
    }
}
