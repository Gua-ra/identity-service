package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when a two-step verification factor is refused for being too new: the
 * account's PIN was created, changed or reset inside the fresh-2FA hold, so it
 * cannot yet be spent as the step-up factor on a phone-number change.
 *
 * <p>
 * Distinct from {@code PhoneChangeCooldownException}, which is the separate
 * minimum gap between two successful phone changes. This one is about how old the
 * factor is, not about how recently the number moved, and it never replaces that
 * cooldown.
 *
 * <p>
 * Carries the remaining seconds so the caller can render a wait, which is the
 * {@code retryAfterSeconds} both clients already read alongside the
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
