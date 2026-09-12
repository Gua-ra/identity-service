package me.sarahlacerda.gua.identityservice.service.security;

/**
 * A factor this service can require, accept or fall back to.
 *
 * <p>
 * Ordered strongest first, and that order is the whole point: {@link AuthFactorPolicy}
 * reads it to answer which factor an account prefers and which one outranks which on a
 * privileged operation, so the ranking lives in one place instead of being re-decided at
 * every call site.
 *
 * <p>
 * Every value here means <b>registered on the server</b>. None of them means "usable on
 * the device making this call". That distinction is not cosmetic: whether an account holds
 * a passkey is something this service can look up and an attacker cannot assert, while
 * whether a passkey can be used right now is only ever a claim made by the client. A
 * client claim can be made by anyone holding a session, so it is never allowed to select a
 * weaker factor. See {@link AuthFactorPolicy} for what follows from that.
 */
public enum AuthFactor {

    /**
     * A WebAuthn credential registered to the account. Strongest, because a step-up
     * assertion additionally proves the human was verified by the authenticator.
     */
    PASSKEY,

    /**
     * The account PIN. A knowledge factor that counts its failures and locks out, and the
     * fallback for everyone who cannot use a passkey.
     */
    PIN,

    /**
     * An SMS code to the number on file. Enough to sign in and to re-authenticate, and
     * deliberately NOT enough on its own to re-point the number it is delivered to, since
     * that is exactly what a SIM swap takes away.
     */
    PHONE_OTP
}
