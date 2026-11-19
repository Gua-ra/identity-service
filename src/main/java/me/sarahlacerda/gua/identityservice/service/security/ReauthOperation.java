package me.sarahlacerda.gua.identityservice.service.security;

/**
 * The privileged operation a single-use reauth token is scoped to, so a token minted for one
 * operation cannot be spent on another. The scope is stored with the bound user id and re-checked
 * on {@link ReauthTokenService#consume(String, String, ReauthOperation)}.
 */
public enum ReauthOperation {
    DEACTIVATE,
    IDENTITY_RESET,
    PHONE_CHANGE
}
