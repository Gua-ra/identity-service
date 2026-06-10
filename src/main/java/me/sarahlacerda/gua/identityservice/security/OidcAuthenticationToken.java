package me.sarahlacerda.gua.identityservice.security;

import java.util.Collections;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;

public class OidcAuthenticationToken extends AbstractAuthenticationToken {

    private final OidcAuthenticatedPrincipal principal;
    private final String accessToken;

    public OidcAuthenticationToken(OidcAuthenticatedPrincipal principal, String accessToken) {
        super(Collections.emptyList());
        this.principal = Objects.requireNonNull(principal, "principal must not be null");
        this.accessToken = Objects.requireNonNull(accessToken, "accessToken must not be null");
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public String getName() {
        return principal.userId();
    }

    public String getAccessToken() {
        return accessToken;
    }
}
