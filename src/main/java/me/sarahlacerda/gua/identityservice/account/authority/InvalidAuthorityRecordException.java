// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

/**
 * Raised by {@link AuthorityRecordCodec}. Carries a stable {@link #reason()} token, in the shape
 * {@code InvalidGenesisException} established, so a client implementing the codec can tell which rule
 * refused its record and a published vector file can name that rule.
 *
 * <p>The message never contains key material or the offending bytes. A decoder failure reaches the
 * caller as one opaque error code with the rule name appended, never as the bytes echoed back.
 */
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

    /** Stable machine-readable rule name, for example {@code wrong_length} or {@code duplicate_keys}. */
    public String reason() {
        return reason;
    }
}
