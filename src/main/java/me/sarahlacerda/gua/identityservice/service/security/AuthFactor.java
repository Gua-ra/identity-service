package me.sarahlacerda.gua.identityservice.service.security;

/**
 * A factor this service can require, accept or fall back to.
 *
 * <p>Ordered strongest first; {@link AuthFactorPolicy} relies on the order.
 *
 * <p>Every value means <b>registered on the server</b>, never usable on the calling device. Whether
 * a passkey can be used right now is only a client claim, so it is never allowed to select a
 * weaker factor.
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
     * An SMS code to the number on file. Not enough on its own to change the number it is delivered
     * to, since that is what a SIM swap takes away.
     */
    PHONE_OTP
}
