package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;
import java.util.Set;

public record OidcAuthenticatedPrincipal(
        String userId,
        String phoneNumber,
        String displayName,
        String preferredUsername,
        Set<String> scope) {
    public OidcAuthenticatedPrincipal {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        scope = Set.copyOf(scope);
    }

    /** Backward-compatible form for principals without a preferred username. */
    public OidcAuthenticatedPrincipal(String userId, String phoneNumber, String displayName, Set<String> scope) {
        this(userId, phoneNumber, displayName, null, scope);
    }
}
