package me.sarahlacerda.gua.identityservice.service;

import me.sarahlacerda.gua.identityservice.metrics.OtpVerifyFlow;

/**
 * Namespace of a one-time code that belongs to a specific flow instead of a phone number.
 *
 * <p>The public {@code POST /otp/send} is unauthenticated and writes the per-phone key
 * {@code otp:code:{e164}}, so a flow verifying against that key would accept a code anyone could
 * request. A scoped code lives under {@code otp:code:{scope}:{id}}, which the public send cannot
 * reach, so it can be satisfied only by the code the flow itself sent.
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
