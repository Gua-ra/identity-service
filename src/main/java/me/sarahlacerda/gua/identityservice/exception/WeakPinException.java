package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when a candidate PIN fails the strength policy (too short or long, repeated, sequential or
 * commonly chosen). Extends {@link InvalidPinException} so existing handlers keep working, while
 * the API surfaces a distinct {@code weak_pin} code (separate from {@code invalid_pin}).
 */
public class WeakPinException extends InvalidPinException {

    public WeakPinException(String message) {
        super(message);
    }
}
