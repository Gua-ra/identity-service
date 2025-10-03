package me.sarahlacerda.gua.identityservice.security;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class MatrixAuthentication extends AbstractAuthenticationToken {

    private final String userId;
    private final String accessToken;

    public MatrixAuthentication(String userId, String accessToken) {
        super(Collections.emptyList());
        this.userId = userId;
        this.accessToken = accessToken;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }
}
