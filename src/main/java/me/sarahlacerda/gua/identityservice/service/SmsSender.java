package me.sarahlacerda.gua.identityservice.service;

import java.util.Locale;

public interface SmsSender {
    void send(String e164PhoneNumber, String messageBody);

    static String providerTag(SmsSender sender) {
        return sender.getClass().getSimpleName().replace("SmsSender", "").toLowerCase(Locale.ROOT);
    }
}
