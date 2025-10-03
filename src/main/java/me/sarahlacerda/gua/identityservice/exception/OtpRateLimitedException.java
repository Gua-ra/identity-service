package me.sarahlacerda.gua.identityservice.exception;

public class OtpRateLimitedException extends RuntimeException {

    public OtpRateLimitedException(String message) {
        super(message);
    }

    public OtpRateLimitedException(String message, Throwable cause) {
        super(message, cause);
    }
}
