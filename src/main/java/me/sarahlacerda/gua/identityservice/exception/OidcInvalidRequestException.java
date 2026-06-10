package me.sarahlacerda.gua.identityservice.exception;

public class OidcInvalidRequestException extends RuntimeException {
    private final String oauthErrorCode;

    public OidcInvalidRequestException(String oauthErrorCode, String message) {
        super(message);
        this.oauthErrorCode = oauthErrorCode;
    }

    public String getOauthErrorCode() {
        return oauthErrorCode;
    }
}
