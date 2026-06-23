package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when a phone-number change is attempted before the per-account cooldown
 * has elapsed. Carries the remaining seconds so the handler can surface a
 * Retry-After. Mapped to HTTP 425 (Too Early), mirroring the PIN-change cooldown.
 */
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
