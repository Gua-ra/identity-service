package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when an incoming phone number cannot be parsed and normalized to a
 * valid E.164 value (e.g. no country code and no match for the default region).
 * Surfaced as a {@code 400 invalid_phone_number} so the client can prompt the
 * user to correct the number.
 */
public class InvalidPhoneNumberException extends RuntimeException {
    public InvalidPhoneNumberException(String message) {
        super(message);
    }
}
