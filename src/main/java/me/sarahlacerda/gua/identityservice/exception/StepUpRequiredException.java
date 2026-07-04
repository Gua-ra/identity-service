package me.sarahlacerda.gua.identityservice.exception;

/**
 * Thrown when a privileged operation demands a non-phone step-up factor
 * (account PIN or passkey) and the account has neither configured. The caller
 * must set up two-step verification before retrying.
 */
public class StepUpRequiredException extends RuntimeException {

    public StepUpRequiredException(String message) {
        super(message);
    }
}
