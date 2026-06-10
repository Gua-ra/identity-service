package me.sarahlacerda.gua.identityservice.service.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;

public record OidcTokenResponse(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("expires_in") long expiresIn,
    @JsonProperty("scope") String scope,
    @JsonProperty("token_type") String tokenType,
    @JsonProperty("id_token") String idToken
) {}
