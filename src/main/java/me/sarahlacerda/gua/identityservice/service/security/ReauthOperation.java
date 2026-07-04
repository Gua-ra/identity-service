package me.sarahlacerda.gua.identityservice.service.security;

/**
 * The privileged operation a single-use reauth token is scoped to. Binding a
 * reauth proof to a specific operation closes a confused-deputy hole: a token
 * minted to authorize (say) a deactivate must not be spendable on a phone
 * change. The scope is stored alongside the bound user id and re-checked on
 * {@link ReauthTokenService#consume(String, String, ReauthOperation)}.
 */
public enum ReauthOperation {
    DEACTIVATE,
    IDENTITY_RESET,
    PHONE_CHANGE
}
