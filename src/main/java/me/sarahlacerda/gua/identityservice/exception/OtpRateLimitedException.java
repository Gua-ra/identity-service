package me.sarahlacerda.gua.identityservice.exception;

import java.time.Duration;

public class OtpRateLimitedException extends RuntimeException {

    private final Duration retryAfter;

    public OtpRateLimitedException(String message) {
        this(message, (Duration) null);
    }

    public OtpRateLimitedException(String message, Throwable cause) {
        super(message, cause);
        this.retryAfter = null;
    }

    public OtpRateLimitedException(String message, Duration retryAfter) {
        super(message);
        this.retryAfter = retryAfter;
    }

    /** How long until the limit that refused the send reopens, or null when unknown. */
    public Duration getRetryAfter() {
        return retryAfter;
    }
}
