package me.sarahlacerda.gua.identityservice.web.ratelimit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class RateLimitingInterceptor implements HandlerInterceptor {

    private final EndpointRateLimiter endpointRateLimiter;

    public RateLimitingInterceptor(EndpointRateLimiter endpointRateLimiter) {
        this.endpointRateLimiter = endpointRateLimiter;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        Optional<EndpointRateLimiter.ResolvedLimiter> resolvedLimiter = endpointRateLimiter.resolve(request);
        if (resolvedLimiter.isEmpty()) {
            return true;
        }

        EndpointRateLimiter.ResolvedLimiter limiter = resolvedLimiter.get();
        boolean permitted = limiter.rateLimiter().acquirePermission();
        if (permitted) {
            return true;
        }

        applyThrottleResponse(response, limiter.refreshPeriod());
        return false;
    }

    private void applyThrottleResponse(HttpServletResponse response, Duration retryAfter) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.reset();
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        long retrySeconds = Math.max(1, retryAfter.toSeconds());
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retrySeconds));
        response.getWriter().write("{\"message\":\"Rate limit exceeded\"}");
    }
}
