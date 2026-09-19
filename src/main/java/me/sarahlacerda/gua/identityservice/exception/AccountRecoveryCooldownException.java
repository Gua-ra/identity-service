package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when a delayed account recovery is requested for an account that completed a sign-in
 * inside the dormancy period. Carries the seconds until it may be requested, measured to the
 * rounded availability time the login state publishes, so the wait never gives away the exact
 * time of the last sign-in. Mapped to 400 {@code recovery_cooldown_active}, the same shape as
 * {@code twofa_cooldown_active}.
 */
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
