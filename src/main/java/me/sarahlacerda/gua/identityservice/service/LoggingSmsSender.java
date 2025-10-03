package me.sarahlacerda.gua.identityservice.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class LoggingSmsSender implements SmsSender {

    private static final Logger log = LoggerFactory.getLogger(LoggingSmsSender.class);

    @Override
    public void send(String e164PhoneNumber, String messageBody) {
        log.info("Pretending to send SMS to {} with body: {}", e164PhoneNumber, messageBody);
    }
}
