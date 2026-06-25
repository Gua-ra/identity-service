package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when the SMS provider cannot deliver a verification code to the phone
 * number's region — e.g. Twilio geo-permissions are not enabled for that country
 * (Twilio error 21408). Surfaced as a {@code 400 phone_region_unsupported} so the
 * client shows a clear "we don't support that country yet" message instead of a
 * generic 500.
 */
public class SmsRegionNotSupportedException extends RuntimeException {
    public SmsRegionNotSupportedException(String message, Throwable cause) {
        super(message, cause);
    }
}
