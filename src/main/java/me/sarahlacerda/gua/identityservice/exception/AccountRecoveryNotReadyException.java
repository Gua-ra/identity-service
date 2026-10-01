package me.sarahlacerda.gua.identityservice.exception;

import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState;

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
