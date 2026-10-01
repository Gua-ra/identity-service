// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.exception;

import org.springframework.http.HttpStatus;

/** Carries a status and a stable error code. Messages must not name the key, device or account. */
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

    public Long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
