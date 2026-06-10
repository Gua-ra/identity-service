package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;
import java.util.Optional;

public record OidcAuthorizationCode(
    String code,
    OidcAuthorization authorization,
    String redirectUri,
    Optional<String> codeChallenge
) {
    public OidcAuthorizationCode {
        Objects.requireNonNull(code, "code must not be null");
        Objects.requireNonNull(authorization, "authorization must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        codeChallenge = codeChallenge == null ? Optional.empty() : codeChallenge;
    }

    public OidcAuthorizationCode(String code, OidcAuthorization authorization, String redirectUri) {
        this(code, authorization, redirectUri, Optional.empty());
    }
}
