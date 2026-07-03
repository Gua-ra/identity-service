package me.sarahlacerda.gua.identityservice.service;

import java.util.Locale;

public interface SmsSender {
    void send(String e164PhoneNumber, String messageBody);

    /**
     * The {@code provider} tag value used on the {@code gua_identity_sms_send_total}
     * metric, derived from the implementation class name (e.g.
     * {@link TwilioSmsSender} -> {@code "twilio"}, {@link LoggingSmsSender} ->
     * {@code "logging"}). Shared by {@link OtpService} (which increments the
     * counter) and the startup metrics initializer (which pre-registers it) so
     * both always agree on the tag value.
     */
    static String providerTag(SmsSender sender) {
        return sender.getClass().getSimpleName().replace("SmsSender", "").toLowerCase(Locale.ROOT);
    }
}
