package me.sarahlacerda.gua.identityservice.service;

public interface SmsSender {
    void send(String e164PhoneNumber, String messageBody);
}
