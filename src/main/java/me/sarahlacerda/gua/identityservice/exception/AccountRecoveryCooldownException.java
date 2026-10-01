package me.sarahlacerda.gua.identityservice.exception;

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
