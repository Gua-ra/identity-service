package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;
import java.util.Set;

public record OidcAuthorization(
        String userId,
        String phoneNumber,
        String displayName,
        String preferredUsername,
        Set<String> scope,
        String clientId,
        String nonce) {

    public OidcAuthorization {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        scope = Set.copyOf(scope);
    }

    /**
     * Backward-compatible form for authorizations without a chosen username or
     * nonce.
     */
    public OidcAuthorization(String userId, String phoneNumber, String displayName, Set<String> scope,
            String clientId) {
        this(userId, phoneNumber, displayName, null, scope, clientId, null);
    }

    public String scopeAsString() {
        return scope.stream().sorted().collect(java.util.stream.Collectors.joining(" "));
    }
}
