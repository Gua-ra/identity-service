package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;
import java.util.Set;

public record OidcAuthenticatedPrincipal(
        String userId,
        String phoneNumber,
        String displayName,
        Set<String> scope) {
    public OidcAuthenticatedPrincipal {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        scope = Set.copyOf(scope);
    }
}
