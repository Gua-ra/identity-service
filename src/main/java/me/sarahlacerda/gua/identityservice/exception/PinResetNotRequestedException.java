package me.sarahlacerda.gua.identityservice.exception;

public class PinResetNotRequestedException extends RuntimeException {

    public PinResetNotRequestedException(String message) {
        super(message);
    }
}
