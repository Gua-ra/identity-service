package me.sarahlacerda.gua.identityservice.service.security;

/** A reauth token is bound to one operation, so a token minted for one cannot be spent on another. */
public enum ReauthOperation {
    DEACTIVATE,
    IDENTITY_RESET,
    PHONE_CHANGE
}
