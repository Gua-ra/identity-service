package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;

@Component
public class RateLimiter {

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
}
