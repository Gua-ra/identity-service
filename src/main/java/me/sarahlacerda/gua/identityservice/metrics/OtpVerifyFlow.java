package me.sarahlacerda.gua.identityservice.metrics;

import java.util.List;

/**
 * Where a verified code was spent, as the {@code flow} tag of
 * {@code gua_identity_otp_verify_total}.
 *
 * <p>
 * One place, because Micrometer keys a meter by its name alone: a counter name first
 * registered with {@code [result]} refuses every later registration that carries
 * {@code [result, flow]}, and the refusal is one warning followed by silence. That is
 * how the phone-change flow's verify counter came to record nothing at all. Anything
 * that verifies a code tags it from here, so the tag set cannot drift apart again.
 */
public enum OtpVerifyFlow {

    /** A code sent to the account's own number: sign-in, reauthentication, enrollment. */
    PHONE("phone"),
    /** The code that completes a PIN change. */
    PIN_CHANGE("pin-change"),
    /** The code that completes a phone-number change, sent to the new number. */
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
