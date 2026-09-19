package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.Objects;
import java.util.Set;

/**
 * A resolved sign-in, carried from the authorization code to the tokens.
 *
 * @param endOtherSessions set only when the sign-in completed a delayed account recovery. The ID
 *                         token then carries {@code gua_end_other_sessions: true}, which the
 *                         authentication service acts on by ending every other session of the
 *                         account. False for every other sign-in
 */
public record OidcAuthorization(
        String userId,
        String phoneNumber,
        String displayName,
        String preferredUsername,
        Set<String> scope,
        String clientId,
        String nonce,
        boolean endOtherSessions) {

    public OidcAuthorization {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        scope = Set.copyOf(scope);
    }

    /** Every sign-in except a completed account recovery. */
    public OidcAuthorization(String userId, String phoneNumber, String displayName, String preferredUsername,
            Set<String> scope, String clientId, String nonce) {
        this(userId, phoneNumber, displayName, preferredUsername, scope, clientId, nonce, false);
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
