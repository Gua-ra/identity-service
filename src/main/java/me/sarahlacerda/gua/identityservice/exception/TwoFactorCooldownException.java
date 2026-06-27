package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when a change-phone OTP is requested while the post-PIN-write 2FA cooldown
 * is still active. Defense-in-depth: the client also pre-checks
 * {@code changePhoneCooldownRemainingSeconds} from /security/pin/status, but the server
 * enforces it again so a SIM-swapper who just set a PIN cannot get instant trust.
 */
public class TwoFactorCooldownException extends RuntimeException {

    private final long retryAfterSeconds;

    public TwoFactorCooldownException(String message, long retryAfterSeconds) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
