package me.sarahlacerda.gua.identityservice.metrics;

import java.util.List;

public enum OtpVerifyFlow {

    PHONE("phone"),
    PIN_CHANGE("pin-change"),
    PHONE_CHANGE("phone-change");

    private final String tagValue;

    OtpVerifyFlow(String tagValue) {
        this.tagValue = tagValue;
    }

    public String tagValue() {
        return tagValue;
    }

    public static List<String> tagValues() {
        return List.of(PHONE.tagValue, PIN_CHANGE.tagValue, PHONE_CHANGE.tagValue);
    }
}
