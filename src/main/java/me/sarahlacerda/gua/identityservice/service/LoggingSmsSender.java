package me.sarahlacerda.gua.identityservice.service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Development {@link SmsSender} that logs the message instead of dialling out.
 * Used whenever Twilio is disabled ({@code identity.sms.twilio.enabled=false}),
 * i.e. local/dev only — production wires {@link TwilioSmsSender}.
 * <p>
 * To make the verification code easy to find while testing locally, it prints a
 * prominent, easy-to-grep banner with the code isolated on its own line. Filter
 * your logs for {@code GUA OTP} (or use {@code scripts/otp.sh}).
 */
@Component
public class LoggingSmsSender implements SmsSender {

    private static final Logger log = LoggerFactory.getLogger(LoggingSmsSender.class);

    /** First run of 4–8 digits in the rendered message — the verification code. */
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
