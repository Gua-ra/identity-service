package me.sarahlacerda.gua.identityservice.service;

import me.sarahlacerda.gua.identityservice.metrics.OtpVerifyFlow;

/** A scoped code lives under otp:code:{scope}:{id}, which the unauthenticated POST /otp/send cannot write. */
public enum OtpScope {

    PIN_CHANGE("pin-change", OtpVerifyFlow.PIN_CHANGE);

    private final String keySegment;
    private final OtpVerifyFlow verifyFlow;

    OtpScope(String keySegment, OtpVerifyFlow verifyFlow) {
        this.keySegment = keySegment;
        this.verifyFlow = verifyFlow;
    }

    public OtpVerifyFlow verifyFlow() {
        return verifyFlow;
    }

    public String keySegment() {
        return keySegment;
    }
}
