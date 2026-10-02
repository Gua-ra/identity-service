package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised by an endpoint that has been retired and now does nothing but say so. Mapped to 410
 * {@code endpoint_retired}.
 */
public class EndpointRetiredException extends RuntimeException {

    public EndpointRetiredException(String message) {
        super(message);
    }
}
