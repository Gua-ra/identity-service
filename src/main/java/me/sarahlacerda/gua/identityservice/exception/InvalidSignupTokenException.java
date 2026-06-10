package me.sarahlacerda.gua.identityservice.exception;

public class InvalidSignupTokenException extends RuntimeException {
    public InvalidSignupTokenException(String message) {
        super(message);
    }
}
