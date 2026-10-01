package me.sarahlacerda.gua.identityservice.exception;

/** The wait is measured to the rounded availability time, so it never reveals the exact time of the last sign-in. */
public class AccountRecoveryCooldownException extends RuntimeException {

    private final long remainingSeconds;

    public AccountRecoveryCooldownException(String message, long remainingSeconds) {
        super(message);
        this.remainingSeconds = remainingSeconds;
    }

    public long getRemainingSeconds() {
        return remainingSeconds;
    }
}
