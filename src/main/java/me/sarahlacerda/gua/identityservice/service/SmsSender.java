package me.sarahlacerda.gua.identityservice.service;

import java.util.Locale;

public interface SmsSender {
    void send(String e164PhoneNumber, String messageBody);

    /** Shared by OtpService and the metrics initializer so both use the same tag value. */
    static String providerTag(SmsSender sender) {
        return sender.getClass().getSimpleName().replace("SmsSender", "").toLowerCase(Locale.ROOT);
    }
}
