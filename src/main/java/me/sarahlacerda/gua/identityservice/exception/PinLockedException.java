package me.sarahlacerda.gua.identityservice.exception;

public class PinLockedException extends RuntimeException {

    private final long remainingSeconds;

    public PinLockedException(String message, long remainingSeconds) {
        super(message);
        this.remainingSeconds = remainingSeconds;
    }

    public long getRemainingSeconds() {
        return remainingSeconds;
    }
}
