package me.sarahlacerda.gua.identityservice.exception;

public class PinResetCooldownException extends RuntimeException {

    private final long remainingSeconds;

    public PinResetCooldownException(String message, long remainingSeconds) {
        super(message);
        this.remainingSeconds = remainingSeconds;
    }

    public long getRemainingSeconds() {
        return remainingSeconds;
    }
}
