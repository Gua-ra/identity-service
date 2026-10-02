package me.sarahlacerda.gua.identityservice.account.genesis;

/**
 * Raised by every strict decoder in this package. Carries a stable {@link #reason()} code naming the
 * rule that fired. The message never contains key material or the offending bytes.
 */
public class InvalidGenesisException extends RuntimeException {

    private final String reason;

    public InvalidGenesisException(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public InvalidGenesisException(String reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    /** Stable machine-readable rule name, e.g. {@code wrong_length} or {@code duplicate_keys}. */
    public String reason() {
        return reason;
    }
}
