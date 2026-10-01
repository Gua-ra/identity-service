// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

/** Carries a stable reason token. Messages must not contain key material or the offending bytes. */
public class InvalidAuthorityRecordException extends RuntimeException {

    private final String reason;

    public InvalidAuthorityRecordException(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public InvalidAuthorityRecordException(String reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
