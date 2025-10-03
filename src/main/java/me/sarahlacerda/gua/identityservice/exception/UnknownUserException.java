package me.sarahlacerda.gua.identityservice.exception;

public class UnknownUserException extends RuntimeException {

    public UnknownUserException(String message) {
        super(message);
    }
}
