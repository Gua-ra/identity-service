package me.sarahlacerda.gua.identityservice.exception;

public class PhoneChangeCooldownException extends RuntimeException {

    private final long remainingSeconds;

    public PhoneChangeCooldownException(String message, long remainingSeconds) {
        super(message);
        this.remainingSeconds = remainingSeconds;
    }

    public long getRemainingSeconds() {
        return remainingSeconds;
    }
}
