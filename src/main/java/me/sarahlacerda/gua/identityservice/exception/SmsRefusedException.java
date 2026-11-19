package me.sarahlacerda.gua.identityservice.exception;

/**
 * The SMS provider refused the destination, so nothing was texted. The reason is a
 * {@code gua_identity_sms_refused_total} tag value and picks the client error.
 */
public class SmsRefusedException extends RuntimeException {

    public enum Reason {
        /** The account may not text this region, or has no sender that reaches it. */
        DESTINATION_UNAVAILABLE("destination_unavailable"),
        /** Not a valid number, or not a mobile number. */
        INVALID_NUMBER("invalid_number"),
        /** The recipient opted out of texts from this sender. */
        RECIPIENT_OPTED_OUT("recipient_opted_out");

        private final String tagValue;

        Reason(String tagValue) {
            this.tagValue = tagValue;
        }

        public String tagValue() {
            return tagValue;
        }
    }

    private final Reason reason;

    public SmsRefusedException(Reason reason) {
        super("SMS provider refused the destination: " + reason.tagValue());
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
