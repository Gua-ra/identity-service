package me.sarahlacerda.gua.identityservice.exception;

/** Extends InvalidPinException so existing handlers keep working. */
public class WeakPinException extends InvalidPinException {

    public WeakPinException(String message) {
        super(message);
    }
}
