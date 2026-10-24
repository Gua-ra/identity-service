package me.sarahlacerda.gua.identityservice.exception;

import java.time.Duration;

public class RateLimiterException extends RuntimeException {

    private final Duration retryAfter;

    public RateLimiterException(String message) {
        this(message, (Duration) null);
    }

    public RateLimiterException(String message, Throwable cause) {
        super(message, cause);
        this.retryAfter = null;
    }

    public RateLimiterException(String message, Duration retryAfter) {
        super(message);
        this.retryAfter = retryAfter;
    }

    /** How long until the window that refused the call reopens, or null when unknown. */
    public Duration getRetryAfter() {
        return retryAfter;
    }
}
