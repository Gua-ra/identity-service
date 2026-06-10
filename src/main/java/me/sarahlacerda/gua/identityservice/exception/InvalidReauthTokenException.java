package me.sarahlacerda.gua.identityservice.exception;

public class InvalidReauthTokenException extends RuntimeException {

    public InvalidReauthTokenException(String message) {
        super(message);
    }
}
