package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;

@Component
public class RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiter.class);

    /** Decrements a positive counter and keeps its expiry; a missing or spent counter is left alone. */
    private static final RedisScript<Long> REFUND = new DefaultRedisScript<>("""
            local count = tonumber(redis.call('GET', KEYS[1]))
            if count and count > 0 then
              return redis.call('DECR', KEYS[1])
            end
            return 0
            """, Long.class);

    private final StringRedisTemplate redisTemplate;

    public RateLimiter(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void checkRate(String key, int limit, Duration window) {
        Long currentCount;
        try {
            currentCount = redisTemplate.opsForValue().increment(key);
        } catch (DataAccessException ex) {
            throw new RateLimiterException("Failed to update rate limiter", ex);
        }

        if (currentCount != null && currentCount == 1L) {
            redisTemplate.expire(key, window);
        }

        if (currentCount != null && currentCount > limit) {
            throw new RateLimiterException("Rate limit exceeded for key: " + key);
        }
    }

    /**
     * Gives back one call {@link #checkRate} counted, for a call that turned out to cost nothing.
     * The window is unchanged. Best effort: a Redis failure here leaves the call counted.
     */
    public void refund(String key) {
        try {
            redisTemplate.execute(REFUND, List.of(key));
        } catch (DataAccessException ex) {
            log.warn("Could not refund a rate-limited call: {}", ex.getClass().getSimpleName());
        }
    }
}
