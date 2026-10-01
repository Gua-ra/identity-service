package me.sarahlacerda.gua.identityservice.exception;

public class TwoFactorCooldownException extends RuntimeException {

    private final long remainingSeconds;

    public TwoFactorCooldownException(String message, long remainingSeconds) {
        super(message);
        this.remainingSeconds = remainingSeconds;
    }

    public long getRemainingSeconds() {
        return remainingSeconds;
    }
}
