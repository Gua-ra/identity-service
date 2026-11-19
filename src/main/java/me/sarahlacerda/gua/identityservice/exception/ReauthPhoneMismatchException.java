package me.sarahlacerda.gua.identityservice.exception;

/**
 * The number submitted to a reauthentication step is not the number on the caller's own account.
 * One refusal with one message for every way of being wrong, so the caller learns nothing about an
 * account that is not theirs.
 */
public class ReauthPhoneMismatchException extends RuntimeException {

    public ReauthPhoneMismatchException(String message) {
        super(message);
    }
}
