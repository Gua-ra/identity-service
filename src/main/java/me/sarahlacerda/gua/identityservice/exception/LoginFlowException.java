package me.sarahlacerda.gua.identityservice.exception;

import org.springframework.http.HttpStatus;

/**
 * Raised by the interactive OIDC login flow when the login session is missing,
 * expired, in the wrong phase, or fails the CSRF check. Carries the HTTP status
 * and a stable error code surfaced to the {@code gua-idp-web} UI.
 */
public class LoginFlowException extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    public LoginFlowException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }
}
