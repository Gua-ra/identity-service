package me.sarahlacerda.gua.identityservice.service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Development {@link SmsSender} that logs the message instead of sending it. Used whenever Twilio is
 * disabled ({@code identity.sms.twilio.enabled=false}); production wires {@link TwilioSmsSender}.
 * The code is printed on its own line under a {@code GUA OTP} banner, which {@code scripts/otp.sh} greps.
 */
@Component
public class LoggingSmsSender implements SmsSender {

    private static final Logger log = LoggerFactory.getLogger(LoggingSmsSender.class);

    /** First run of 4 to 8 digits in the rendered message: the verification code. */
    private static final Pattern CODE = Pattern.compile("\\b(\\d{4,8})\\b");

    @Override
    public void send(String e164PhoneNumber, String messageBody) {
        Matcher matcher = CODE.matcher(messageBody);
        String code = matcher.find() ? matcher.group(1) : "(see body)";
        log.info("""

                ┌──────────── GUA OTP (dev — not sent via SMS) ────────────
                │  phone : {}
                │  code  : {}
                └──────────────────────────────────────────────────────────
                """, e164PhoneNumber, code);
    }
}
