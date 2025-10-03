package me.sarahlacerda.gua.identityservice.web.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;

class RateLimitingInterceptorTest {

    private EndpointRateLimiter endpointRateLimiter;
    private RateLimitingInterceptor interceptor;

    @BeforeEach
    void setup() {
        endpointRateLimiter = mock(EndpointRateLimiter.class);
        interceptor = new RateLimitingInterceptor(endpointRateLimiter);
    }

    @Test
    void preHandleContinuesWhenPermitAvailable() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        RateLimiterConfig config = RateLimiterConfig.custom()
            .limitForPeriod(10)
            .limitRefreshPeriod(Duration.ofSeconds(1))
            .timeoutDuration(Duration.ZERO)
            .build();
        RateLimiter rateLimiter = RateLimiter.of("test", config);

        when(endpointRateLimiter.resolve(request)).thenReturn(Optional.of(new EndpointRateLimiter.ResolvedLimiter(rateLimiter, Duration.ZERO, Duration.ofSeconds(1))));

        boolean result = interceptor.preHandle(request, response, new Object());

        assertThat(result).isTrue();
        verify(response, never()).setStatus(429);
    }

    @Test
    void preHandleReturns429WhenRateLimitExceeded() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        PrintWriter writer = new PrintWriter(body, true);

        RateLimiterConfig config = RateLimiterConfig.custom()
            .limitForPeriod(1)
            .limitRefreshPeriod(Duration.ofSeconds(30))
            .timeoutDuration(Duration.ZERO)
            .build();
        RateLimiter rateLimiter = RateLimiter.of("test-exhausted", config);
        rateLimiter.acquirePermission(); // consume the only permit

        when(response.getWriter()).thenReturn(writer);
        when(endpointRateLimiter.resolve(request)).thenReturn(Optional.of(new EndpointRateLimiter.ResolvedLimiter(rateLimiter, Duration.ZERO, Duration.ofSeconds(30))));

        boolean result = interceptor.preHandle(request, response, new Object());

        assertThat(result).isFalse();
        verify(response).setStatus(429);
        verify(response).setHeader("Retry-After", "30");
        writer.flush();
        assertThat(body.toString()).contains("Rate limit exceeded");
    }

    @Test
    void preHandleSkipsWhenNoLimiterConfigured() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(endpointRateLimiter.resolve(request)).thenReturn(Optional.empty());

        boolean result = interceptor.preHandle(request, response, new Object());

        assertThat(result).isTrue();
        verify(response, never()).setStatus(429);
    }
}
