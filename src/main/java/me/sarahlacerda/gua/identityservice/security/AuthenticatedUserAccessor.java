package me.sarahlacerda.gua.identityservice.security;

import java.util.Optional;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;

@Component
public class AuthenticatedUserAccessor {

    public Optional<String> currentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof String principalUserId) {
            return Optional.of(principalUserId);
        }
        if (principal instanceof OidcAuthenticatedPrincipal oidcPrincipal) {
            return Optional.ofNullable(oidcPrincipal.userId());
        }
        return Optional.empty();
    }

    /**
     * The registered OIDC client the caller's access token was issued to, when it is one of
     * ours. Empty for a homeserver-issued token, which names no client of ours, and for any
     * caller that is not authenticated by a token at all. The value comes from the token's
     * verified audience, never from anything the caller sends alongside it.
     */
    public Optional<String> currentClientId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }
        return authentication.getPrincipal() instanceof OidcAuthenticatedPrincipal oidcPrincipal
                ? Optional.ofNullable(oidcPrincipal.clientId())
                : Optional.empty();
    }

    public String requireCurrentUserId() {
        return currentUserId().orElseThrow(() -> new AccessDeniedException("Authentication required"));
    }

    public void requireUserIdMatches(String expectedUserId) {
        String actualUserId = requireCurrentUserId();
        if (!actualUserId.equals(expectedUserId)) {
            throw new AccessDeniedException("Token user does not match request user");
        }
    }
}
