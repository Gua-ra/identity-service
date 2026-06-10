package me.sarahlacerda.gua.identityservice.exception;

public class OidcClientAuthenticationException extends RuntimeException {
    public OidcClientAuthenticationException(String message) {
        super(message);
    }
}
