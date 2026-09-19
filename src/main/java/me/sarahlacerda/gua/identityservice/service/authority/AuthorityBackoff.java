// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/**
 * ADM-002 D2's doubling backoff, counted per key set (ADM-009 decisions 3 and 7).
 *
 * <p>Each cancelled initiation doubles the backoff of the key set that opened the cancelled one. That is what
 * stops the cancel itself becoming the attack: a rank-2 record can always land, and it cancels a weaker one,
 * but a holder who cancels repeatedly pays the doubling on their own next initiation.
 *
 * <p>Held in Redis next to the other attempt budgets rather than in a column, because it is a rate rather
 * than a fact about the account: it expires on its own, it is per key set rather than per account, and
 * nothing later needs to audit it. The key is the account and the authorizing key together, so one device's
 * cancelled initiations never charge another's.
 *
 * <p>A counter that cannot be read refuses the initiation rather than waving it through, which is the same
 * choice the reauth attempt budget makes and for the same reason.
 */
@Service
public class AuthorityBackoff {

    private static final String KEY_PREFIX = "authority:backoff:";

    /** Long enough to outlive the largest backoff the policy can hand out, and no longer. */
    private static final Duration RETENTION = Duration.ofDays(30);

    private final StringRedisTemplate redisTemplate;
    private final AuthorityPolicy policy;

    public AuthorityBackoff(StringRedisTemplate redisTemplate, AuthorityPolicy policy) {
        this.redisTemplate = redisTemplate;
        this.policy = policy;
    }

    /** When this key set may initiate again, or empty when it owes nothing. */
    public Optional<Instant> until(String account, String authorizingKeyB64) {
        String value = redisTemplate.opsForValue().get(key(account, authorizingKeyB64));
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(Instant.ofEpochSecond(Long.parseLong(value.split(":", 2)[1])));
        } catch (RuntimeException ex) {
            // An unreadable value is treated as a live backoff rather than as none: a corrupted counter must
            // not be a way through.
            return Optional.of(Instant.MAX);
        }
    }

    /**
     * Records that this key set's initiation was cancelled, and returns when it may initiate again.
     *
     * <p>The count is what doubles. It is kept rather than the instant alone, so a second cancellation
     * charges twice the window and not the same window again.
     */
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
