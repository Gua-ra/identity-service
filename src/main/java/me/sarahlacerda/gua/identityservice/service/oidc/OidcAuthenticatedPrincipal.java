package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;
import java.util.Set;

/**
 * Who the bearer token says the caller is, and which registered OIDC client minted it.
 *
 * @param clientId the registered client the token was issued to, taken from the audience the
 *                 token was accepted on. Null for a token this service did not mint, which is
 *                 every homeserver-issued token: those carry no client of ours, and a caller
 *                 never gets to name one.
 */
public record OidcAuthenticatedPrincipal(
        String userId,
        String phoneNumber,
        String displayName,
        String preferredUsername,
        Set<String> scope,
        String clientId) {
    public OidcAuthenticatedPrincipal {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        scope = Set.copyOf(scope);
    }

    /** Form for principals whose token named no client of ours. */
    public OidcAuthenticatedPrincipal(String userId, String phoneNumber, String displayName,
            String preferredUsername, Set<String> scope) {
        this(userId, phoneNumber, displayName, preferredUsername, scope, null);
    }

    /** Backward-compatible form for principals without a preferred username. */
    public OidcAuthenticatedPrincipal(String userId, String phoneNumber, String displayName, Set<String> scope) {
        this(userId, phoneNumber, displayName, null, scope, null);
    }
}
