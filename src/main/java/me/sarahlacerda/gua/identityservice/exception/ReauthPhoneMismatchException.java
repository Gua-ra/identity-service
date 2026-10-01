package me.sarahlacerda.gua.identityservice.exception;

public class ReauthPhoneMismatchException extends RuntimeException {

    public ReauthPhoneMismatchException(String message) {
        super(message);
    }
}
