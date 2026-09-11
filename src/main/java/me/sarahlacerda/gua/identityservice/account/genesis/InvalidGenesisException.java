package me.sarahlacerda.gua.identityservice.account.genesis;

/**
 * Raised by every strict decoder in this package. Carries a stable {@link #reason()} code so the
 * published golden vectors can name the rule that refuses each rejection case, and so the REST layer
 * can log which rule fired without echoing the bytes back to the caller.
 *
 * <p>The message never contains key material or the offending bytes: a decoder failure is reported to
 * the client as one opaque error code.
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
