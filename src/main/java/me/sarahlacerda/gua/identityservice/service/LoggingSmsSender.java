package me.sarahlacerda.gua.identityservice.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Development {@link SmsSender} that logs instead of dialling out. Used whenever Twilio is
 * disabled ({@code identity.sms.twilio.enabled=false}); production wires {@link TwilioSmsSender}.
 *
 * <p>
 * It logs the masked number and that a code was sent, never the message or the code: a log is
 * not a channel a code may travel through. The live code is in Redis under
 * {@code otp:code:<E.164>} ({@code scripts/otp.sh} reads it there).
 */
@Component
public class LoggingSmsSender implements SmsSender {

    private static final Logger log = LoggerFactory.getLogger(LoggingSmsSender.class);

    private final PhoneNumberMasker masker;

    public LoggingSmsSender(PhoneNumberMasker masker) {
        this.masker = masker;
    }

    @Override
    public void send(String e164PhoneNumber, String messageBody) {
        log.info("Code sent to {}", masker.mask(e164PhoneNumber));
    }
}
