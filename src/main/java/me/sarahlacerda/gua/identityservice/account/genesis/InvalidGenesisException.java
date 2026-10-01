package me.sarahlacerda.gua.identityservice.account.genesis;

/** The message never contains key material or the offending bytes. */
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

    public String reason() {
        return reason;
    }
}
