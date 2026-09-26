// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.exception;

import org.springframework.http.HttpStatus;

/**
 * Raised by the account authority chain (ADM-009) for every outcome that is not a malformed record: the
 * feature is switched off, the session is not native, the step-up is missing or too fresh, the record is
 * refused at this position, a higher or equal rank record is pending, or the backoff is running.
 *
 * <p>Carries the HTTP status and a stable error code, in the shape {@code GenesisRegistrationException}
 * established. A refusal never says which key, which device or which account it was about: the caller is
 * told the rule, and the reason is logged.
 */
public class AuthorityTransitionException extends RuntimeException {

    private final HttpStatus status;
    private final String code;
    private final Long retryAfterSeconds;

    public AuthorityTransitionException(HttpStatus status, String code, String message) {
        this(status, code, message, null);
    }

    public AuthorityTransitionException(HttpStatus status, String code, String message, Long retryAfterSeconds) {
        super(message);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    /** Present on a backoff or a cooldown refusal, so a client waits rather than retrying at once. */
    public Long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
