package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;
import java.util.Set;

public record OidcAuthorizationRequest(
    String clientId,
    String redirectUri,
    Set<String> scope,
    String phoneNumber,
    String otpCode,
    String displayName
) {

    public OidcAuthorizationRequest {
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        Objects.requireNonNull(phoneNumber, "phoneNumber must not be null");
        Objects.requireNonNull(otpCode, "otpCode must not be null");
        scope = Set.copyOf(scope);
    }
}
