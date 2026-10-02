package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when the account's PIN was created, changed or reset inside the fresh-2FA hold, so it
 * cannot yet be spent as the step-up factor on a phone-number change. Distinct from
 * {@code PhoneChangeCooldownException}, the minimum gap between two successful phone changes.
 * Carries the remaining seconds, surfaced as {@code retryAfterSeconds} alongside the
 * {@code twofa_cooldown_active} code.
 */
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
