package me.sarahlacerda.gua.identityservice.exception;

import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState;

/**
 * Raised when completing an account recovery that is not ready at the moment it is re-evaluated
 * under the account's row lock: still waiting, cancelled, expired, or never started. Carries the
 * fresh state so the client can re-render without a second request. Mapped to 409
 * {@code recovery_not_ready}.
 */
public class AccountRecoveryNotReadyException extends RuntimeException {

    private final transient AccountRecoveryState state;

    public AccountRecoveryNotReadyException(String message, AccountRecoveryState state) {
        super(message);
        this.state = state;
    }

    public AccountRecoveryState getState() {
        return state;
    }
}
