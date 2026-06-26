package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when a phone-change challenge presented at
 * {@code /account/phone/change/complete} is missing, expired, or does not belong
 * to the calling user. Mapped to HTTP 401 (the challenge id is the proof of a
 * completed /start step).
 */
public class InvalidPhoneChangeChallengeException extends RuntimeException {

    public InvalidPhoneChangeChallengeException(String message) {
        super(message);
    }
}
