package me.sarahlacerda.gua.identityservice.service;

import me.sarahlacerda.gua.identityservice.metrics.OtpVerifyFlow;

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
 * {@code otp:code:change:{challengeId}}; this is the same idea for the PIN change.
 */
public enum OtpScope {

    /**
     * The OTP that completes an OTP-protected PIN change, keyed by the change challenge
     * handed out at {@code /security/pin/change/start}.
     */
    PIN_CHANGE("pin-change", OtpVerifyFlow.PIN_CHANGE);

    private final String keySegment;
    private final OtpVerifyFlow verifyFlow;

    OtpScope(String keySegment, OtpVerifyFlow verifyFlow) {
        this.keySegment = keySegment;
        this.verifyFlow = verifyFlow;
    }

    /** The flow tag a code spent under this scope is counted with. */
    public OtpVerifyFlow verifyFlow() {
        return verifyFlow;
    }

    /** The {@code {scope}} segment of the Redis key. */
    public String keySegment() {
        return keySegment;
    }
}
