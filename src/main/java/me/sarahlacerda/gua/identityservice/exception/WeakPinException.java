package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when a candidate PIN is well-formed enough to evaluate but fails the
 * strength policy (too short/long, repeated, sequential, or commonly chosen).
 *
 * <p>Extends {@link InvalidPinException} so existing handling that catches
 * invalid PINs keeps working, while allowing the API layer to surface a distinct
 * {@code weak_pin} error code (separate from the {@code invalid_pin} used when a
 * supplied PIN does not match at login).
 */
public class WeakPinException extends InvalidPinException {

    public WeakPinException(String message) {
        super(message);
    }
}
