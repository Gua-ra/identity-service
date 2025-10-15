package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;

public record OidcAuthorizationCode(
    String code,
    OidcAuthorization authorization,
    String redirectUri
) {
    public OidcAuthorizationCode {
        Objects.requireNonNull(code, "code must not be null");
        Objects.requireNonNull(authorization, "authorization must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
    }
}
