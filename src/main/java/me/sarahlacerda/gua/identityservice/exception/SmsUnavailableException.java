package me.sarahlacerda.gua.identityservice.exception;

/**
 * The SMS provider failed for a reason other than refusing the destination. The text may or may
 * not have gone out, so the send stays counted against the send limits.
 */
public class SmsUnavailableException extends RuntimeException {

    public SmsUnavailableException(String message) {
        super(message);
    }
}
