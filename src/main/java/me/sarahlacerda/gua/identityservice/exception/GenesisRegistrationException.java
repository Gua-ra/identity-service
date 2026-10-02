package me.sarahlacerda.gua.identityservice.exception;

import org.springframework.http.HttpStatus;

/**
 * Raised by {@code POST /account/genesis} for outcomes that are not a malformed object: the feature is
 * switched off, the possession proof does not verify, issuance under the offered recovery framework is
 * not permitted yet, or the accountId is already attached to an account.
 *
 * <p>Carries the HTTP status and a stable error code, in the shape {@code LoginFlowException} uses.
 */
public class GenesisRegistrationException extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    public GenesisRegistrationException(HttpStatus status, String code, String message) {
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
