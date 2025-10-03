package me.sarahlacerda.gua.identityservice.service;

import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RateLimiterTest {

    private StringRedisTemplate redisTemplate;
    private ValueOperations<String, String> valueOperations;
    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        redisTemplate = Mockito.mock(StringRedisTemplate.class);
        valueOperations = Mockito.mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        rateLimiter = new RateLimiter(redisTemplate);
    }

    @Test
    void checkRateSetsExpiryOnFirstHit() {
        when(valueOperations.increment("key")).thenReturn(1L);

        rateLimiter.checkRate("key", 5, Duration.ofMinutes(1));

        verify(redisTemplate).expire("key", Duration.ofMinutes(1));
    }

    @Test
    void checkRateThrowsWhenLimitExceeded() {
        when(valueOperations.increment("key")).thenReturn(6L);

        assertThatThrownBy(() -> rateLimiter.checkRate("key", 5, Duration.ofMinutes(1)))
            .isInstanceOf(RateLimiterException.class)
            .hasMessageContaining("Rate limit exceeded");
    }

    @Test
    void checkRateWrapsDataAccessExceptions() {
        when(valueOperations.increment("key")).thenThrow(new DataAccessResourceFailureException("fail"));

        assertThatThrownBy(() -> rateLimiter.checkRate("key", 5, Duration.ofMinutes(1)))
            .isInstanceOf(RateLimiterException.class)
            .hasMessageContaining("Failed to update rate limiter");
    }
}
