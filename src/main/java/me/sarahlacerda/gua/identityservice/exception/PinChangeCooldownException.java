package me.sarahlacerda.gua.identityservice.exception;

public class PinChangeCooldownException extends RuntimeException {

    private final long remainingSeconds;

    public PinChangeCooldownException(String message, long remainingSeconds) {
        super(message);
        this.remainingSeconds = remainingSeconds;
    }

    public long getRemainingSeconds() {
        return remainingSeconds;
    }
}
