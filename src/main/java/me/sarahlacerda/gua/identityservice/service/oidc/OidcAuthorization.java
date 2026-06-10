package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;
import java.util.Set;

public record OidcAuthorization(
    String userId,
    String phoneNumber,
    String displayName,
    Set<String> scope,
    String clientId
) {

    public OidcAuthorization {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(phoneNumber, "phoneNumber must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        scope = Set.copyOf(scope);
    }

    public String scopeAsString() {
        return scope.stream().sorted().collect(java.util.stream.Collectors.joining(" "));
    }
}
