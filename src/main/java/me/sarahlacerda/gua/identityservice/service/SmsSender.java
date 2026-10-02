package me.sarahlacerda.gua.identityservice.service;

import java.util.Locale;

public interface SmsSender {
    void send(String e164PhoneNumber, String messageBody);

    /**
     * The {@code provider} tag value on the {@code gua_identity_sms_send_total} metric, derived from
     * the implementation class name ({@link TwilioSmsSender} gives {@code "twilio"},
     * {@link LoggingSmsSender} gives {@code "logging"}). Shared by {@link OtpService} and the startup
     * metrics initializer so both agree on the tag value.
     */
    static String providerTag(SmsSender sender) {
        return sender.getClass().getSimpleName().replace("SmsSender", "").toLowerCase(Locale.ROOT);
    }
}
