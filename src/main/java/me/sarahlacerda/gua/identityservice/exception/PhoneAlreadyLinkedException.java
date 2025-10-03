package me.sarahlacerda.gua.identityservice.exception;

public class PhoneAlreadyLinkedException extends RuntimeException {
    public PhoneAlreadyLinkedException(String message) {
        super(message);
    }
}