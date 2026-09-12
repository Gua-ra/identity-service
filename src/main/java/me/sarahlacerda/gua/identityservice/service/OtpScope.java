package me.sarahlacerda.gua.identityservice.service;

/**
 * Namespace of a one-time code that belongs to a specific flow rather than to a
 * phone number.
 *
 * <p>
 * The public {@code POST /otp/send} is unauthenticated and writes the per-phone key
 * {@code otp:code:{e164}}. Any flow that verifies against that same key therefore
 * accepts a code anyone could ask for, for any reason, and can have a code planted
 * under it before the flow even starts. A scoped code lives under
 * {@code otp:code:{scope}:{id}} instead, which the public send cannot reach, so it can
 * be satisfied only by the code this flow itself sent.
 *
 * <p>
 * {@code PhoneChangeOtpService} established the shape with
 * {@code otp:code:change:{challengeId}}; these are the same idea for the PIN flows.
 */
public enum OtpScope {

    /**
     * The OTP that completes an OTP-protected PIN change, keyed by the change challenge
     * handed out at {@code /security/pin/change/start}.
     */
    PIN_CHANGE("pin-change"),

    /**
     * The OTP that completes a PIN reset, keyed by account. The reset flow has no
     * challenge id on the wire, and the account is the thing the reset is pending on.
     */
    PIN_RESET("pin-reset");

    private final String keySegment;

    OtpScope(String keySegment) {
        this.keySegment = keySegment;
    }

    /** The {@code {scope}} segment of the Redis key. */
    public String keySegment() {
        return keySegment;
    }
}
