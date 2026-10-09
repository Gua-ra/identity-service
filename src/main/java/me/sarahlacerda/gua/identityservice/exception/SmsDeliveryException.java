package me.sarahlacerda.gua.identityservice.exception;

/** An SMS the provider refused. The message carries the provider's error code and status, never its text. */
public class SmsDeliveryException extends RuntimeException {

    public SmsDeliveryException(String message) {
        super(message);
    }
}
